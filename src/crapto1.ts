export interface Crypto1State {
    odd: number
    even: number
}

export class Crapto1 {
    uid: number = 0;
    chal: number = 0;
    rchal: number = 0;
    rresp: number = 0;
    chal2: number = 0;
    rchal2: number = 0;
    rresp2: number = 0;
    key: bigint = -1n;

    static CraptoData = class{
        uid: number = 0;
        chal: number[] = [];
        rchal: number[] = [];
        rresp: number[] = [];
        key: bigint = -1n;
    }

    Crypto1State = class {
        odd: number = 0;
        even: number = 0;
    }

    filterlut: Uint8Array = new Uint8Array(1 << 20);
    LF_POLY_ODD: number = 0x29CE5C;
    LF_POLY_EVEN: number = 0x870804;

    constructor() {
        for (let i = 0; i < 1 << 20; ++i) {
            this.filterlut[i] = this.filter(i);
        }
    }

    bit(x: number, n: number): number {
        return ((x >>> n) & 1);
    }

    bebit(x: number, n: number): number {
        return ((x >>> (n ^ 24)) & 1);
    }

    filter(x: number): number {
        let f: number = 0;
        f |= (0xf22c0 >>> (x & 0xf) & 16) !== 0 ? 16 : 0;
        f |= (0x6c9c0 >>> (x >>> 4 & 0xf) & 8) !== 0 ? 8 : 0;
        f |= (0x3c8b0 >>> (x >>> 8 & 0xf) & 4) !== 0 ? 4 : 0;
        f |= (0x1e458 >>> (x >>> 12 & 0xf) & 2) !== 0 ? 2 : 0;
        f |= (0x0d938 >>> (x >>> 16 & 0xf) & 1) !== 0 ? 1 : 0;
        return this.bit(0xEC57E80A, f);
    }

    parity(x: number): number {
        x ^= x >>> 16;
        x ^= x >>> 8;
        x ^= x >>> 4;
        return this.bit(0x6996, x & 0xf);
    }

    swapendian(x: number): number {
        x = (x >>> 8 & 0xff00ff) | (x & 0xff00ff) << 8;
        x = x >>> 16 | x << 16;
        return x;
    }

    prng_successor(x: number, n: number): number {
        x = this.swapendian(x);
        while ((n--) > 0) {
            x = x >>> 1 | (x >>> 16 ^ x >>> 18 ^ x >>> 19 ^ x >>> 21) << 31;
        }
        return this.swapendian(x);
    }

    extend_table_simple(data: number[], tbl: number, end: number, bit: number): number {
        for (data[tbl] <<= 1; tbl <= end; data[++tbl] <<= 1) {
            if ((this.filter(data[tbl]) ^ this.filter(data[tbl] | 1)) !== 0) {
                data[tbl] |= this.filter(data[tbl]) ^ bit;
            } else if (this.filter(data[tbl]) === bit) {
                data[++end] = data[++tbl];
                data[tbl] = data[tbl - 1] | 1;
            } else {
                data[tbl--] = data[end--];
            }
        }
        return end;
    }

    lfsr_recovery32(ks2: number, in_: number): Crypto1State[] {
        const statelist: Crypto1State[] = Array.from({ length: 1 << 18 }, () => new this.Crypto1State());
        let stl: number = 0;
        const odd: number[] = Array(1 << 21).fill(0);
        const even: number[] = Array(1 << 21).fill(0);
        let odd_head: number = 0, odd_tail: number = -1, oks: number = 0;
        let even_head: number = 0, even_tail: number = -1, eks: number = 0;

        for (let i = 31; i >= 0; i -= 2) {
            oks = oks << 1 | this.bebit(ks2, i);
        }
        for (let i = 30; i >= 0; i -= 2) {
            eks = eks << 1 | this.bebit(ks2, i);
        }

        statelist[stl].odd = statelist[stl].even = 0;

        for (let i = 1 << 20; i >= 0; --i) {
            if (this.filter(i) === (oks & 1)) {
                odd[++odd_tail] = i;
            }
            if (this.filter(i) === (eks & 1)) {
                even[++even_tail] = i;
            }
        }

        for (let i = 0; i < 4; i++) {
            odd_tail = this.extend_table_simple(odd, odd_head, odd_tail, (oks >>>= 1) & 1);
            even_tail = this.extend_table_simple(even, even_head, even_tail, (eks >>>= 1) & 1);
        }

        in_ = (in_ >>> 16 & 0xff) | (in_ << 16) | (in_ & 0xff00);
        this.recover(odd, odd_head, odd_tail, oks, even, even_head, even_tail, eks, 11, statelist, 0, in_ << 1);
        return statelist;
    }

    extend_table(data: number[], tbl: number, end: number, bit: number, m1: number, m2: number, in_: number): number {
        in_ <<= 24;
        for (data[tbl] <<= 1; tbl <= end; data[++tbl] <<= 1) {
            if ((this.filter(data[tbl]) ^ this.filter(data[tbl] | 1)) !== 0) {
                data[tbl] |= this.filter(data[tbl]) ^ bit;
                this.update_contribution(data, tbl, m1, m2);
                data[tbl] ^= in_;
            } else if (this.filter(data[tbl]) === bit) {
                data[++end] = data[tbl + 1];
                data[tbl + 1] = data[tbl] | 1;
                this.update_contribution(data, tbl, m1, m2);
                data[tbl++] ^= in_;
                this.update_contribution(data, tbl, m1, m2);
                data[tbl] ^= in_;
            } else {
                data[tbl--] = data[end--];
            }
        }
        return end;
    }

    update_contribution(data: number[], item: number, mask1: number, mask2: number): void {
        let p: number = data[item] >>> 25;
        p = p << 1 | this.parity(data[item] & mask1);
        p = p << 1 | this.parity(data[item] & mask2);
        data[item] = p << 24 | (data[item] & 0xffffff);
    }

    quicksort(data: number[], start: number, stop: number): void {
        let it: number = start + 1, rit: number = stop, t: number;
        if (it > rit) return;
        while (it < rit) {
            if ((data[it] ^ 0x80000000) <= (data[start] ^ 0x80000000)) {
                ++it;
            } else if ((data[rit] ^ 0x80000000) > (data[start] ^ 0x80000000)) {
                --rit;
            } else {
                t = data[it];
                data[it] = data[rit];
                data[rit] = t;
            }
        }
        if ((data[rit] ^ 0x80000000) >= (data[start] ^ 0x80000000)) {
            --rit;
        }
        if (rit !== start) {
            t = data[rit];
            data[rit] = data[start];
            data[start] = t;
        }
        this.quicksort(data, start, rit - 1);
        this.quicksort(data, rit + 1, stop);
    }

    recover(odd: number[], o_head: number, o_tail: number, oks: number, even: number[], e_head: number, e_tail: number, eks: number, rem: number, sl: Crypto1State[], s: number, in_: number): number {
        let o: number, e: number, i: number;
        if (rem === -1) {
            for (e = e_head; e <= e_tail; ++e) {
                even[e] = even[e] << 1 ^ this.parity(even[e] & this.LF_POLY_EVEN) ^ (((in_ & 4) !== 0) ? 1 : 0);
                for (o = o_head; o <= o_tail; ++o, ++s) {
                    sl[s].even = odd[o];
                    sl[s].odd = even[e] ^ this.parity(odd[o] & this.LF_POLY_ODD);
                    sl[s + 1].odd = sl[s + 1].even = 0;
                }
            }
            return s;
        }
        for (i = 0; (i < 4) && (rem-- !== 0); i++) {
            oks >>>= 1;
            eks >>>= 1;
            in_ >>>= 2;
            o_tail = this.extend_table(odd, o_head, o_tail, oks & 1, this.LF_POLY_EVEN << 1 | 1, this.LF_POLY_ODD << 1, 0);
            if (o_head > o_tail) return s;
            e_tail = this.extend_table(even, e_head, e_tail, eks & 1, this.LF_POLY_ODD, this.LF_POLY_EVEN << 1 | 1, in_ & 3);
            if (e_head > e_tail) return s;
        }
        this.quicksort(odd, o_head, o_tail);
        this.quicksort(even, e_head, e_tail);
        while (o_tail >= o_head && e_tail >= e_head) {
            if (((odd[o_tail] ^ even[e_tail]) >>> 24) === 0) {
                o_tail = this.binsearch(odd, o_head, o = o_tail);
                e_tail = this.binsearch(even, e_head, e = e_tail);
                s = this.recover(odd, o_tail--, o, oks, even, e_tail--, e, eks, rem, sl, s, in_);
            } else if ((odd[o_tail] ^ 0x80000000) > (even[e_tail] ^ 0x80000000)) {
                o_tail = this.binsearch(odd, o_head, o_tail) - 1;
            } else {
                e_tail = this.binsearch(even, e_head, e_tail) - 1;
            }
        }
        return s;
    }

    binsearch(data: number[], start: number, stop: number): number {
        let mid: number, val: number = data[stop] & 0xff000000;
        while (start !== stop) {
            mid = (stop - start) >> 1;
            if ((data[start + mid] ^ 0x80000000) > (val ^ 0x80000000)) {
                stop = start + mid;
            } else {
                start += mid + 1;
            }
        }
        return start;
    }

    lfsr_rollback_bit(s: Crypto1State[], j: number, in_: number, fb: number): number {
        let out: number;
        let ret: number;
        let t: number;
        s[j].odd &= 0xffffff;
        t = s[j].odd;
        s[j].odd = s[j].even;
        s[j].even = t;
        out = s[j].even & 1;
        out ^= this.LF_POLY_EVEN & (s[j].even >>= 1);
        out ^= this.LF_POLY_ODD & s[j].odd;
        out ^= (in_ !== 0) ? 1 : 0;
        out ^= (ret = this.filter(s[j].odd)) & ((fb !== 0) ? 1 : 0);
        s[j].even |= this.parity(out) << 23;
        return ret;
    }

    lfsr_rollback_word(s: Crypto1State[], t: number, in_: number, fb: number): number {
        let i: number;
        let ret: number = 0;
        for (i = 31; i >= 0; --i) {
            ret |= this.lfsr_rollback_bit(s, t, this.bebit(in_, i), fb) << (i ^ 24);
        }
        return ret;
    }

    crypto1_get_lfsr(state: Crypto1State[], t: number, lfsr: bigint) {
        let i: number;
        for (lfsr = 0n, i = 23; i >= 0; --i) {
            lfsr = lfsr << 1n | BigInt(this.bit(state[t].odd, i ^ 3));
            lfsr = lfsr << 1n | BigInt(this.bit(state[t].even, i ^ 3));
        }
        return lfsr;
    }

    crypto1_word(s: Crypto1State[], t: number, in_: number, is_encrypted: number): number {
        let i: number, ret: number = 0;
        for (i = 0; i < 32; ++i) {
            ret |= this.crypto1_bit(s, t, this.bebit(in_, i), is_encrypted) << (i ^ 24);
        }
        return ret;
    }

    crypto1_bit(s: Crypto1State[], t: number, in_: number, is_encrypted: number): number {
        let feedin: number;
        let ret: number = this.filter(s[t].odd);
        feedin = ret & ((is_encrypted !== 0) ? 1 : 0);
        feedin ^= ((in_ !== 0) ? 1 : 0);
        feedin ^= this.LF_POLY_ODD & s[t].odd;
        feedin ^= this.LF_POLY_EVEN & s[t].even;
        s[t].even = s[t].even << 1 | this.parity(feedin);
        s[t].odd ^= s[t].even;
        s[t].even ^= s[t].odd;
        s[t].odd ^= s[t].even;
        return ret;
    }

    /**
     * Recovery by two sets of 32 bit keystream authentication
     * @returns {boolean}
     */
    RecoveryKey32(): boolean {
        const s = this.lfsr_recovery32(this.rresp ^ this.prng_successor(this.chal, 64), 0);
        let t: number;
        for (t = 0; (s[t].odd !== 0) || (s[t].even !== 0); ++t) {
            this.lfsr_rollback_word(s, t, 0, 0);
            this.lfsr_rollback_word(s, t, this.rchal, 1);
            this.lfsr_rollback_word(s, t, this.uid ^ this.chal, 0);
            this.key = this.crypto1_get_lfsr(s, t, this.key);
            this.crypto1_word(s, t, this.uid ^ this.chal2, 0);
            this.crypto1_word(s, t, this.rchal2, 1);
            if (this.rresp2 === (this.crypto1_word(s, t, 0, 0) ^ this.prng_successor(this.chal2, 64))) {
                return true;
            }
        }
        return false;
    }
}

/**
 * Recovery by two sets of 32 bit keystream authentication
 * @param uid UID
 * @param chal Tag challenge #1 (aka `nt`)
 * @param rchal Reader challenge #1 (aka `nr_0`)
 * @param rresp Reader response #1 (aka `ar_0`)
 * @param chal2 Tag challenge #2 (aka `nt1`)
 * @param rchal2 Reader challenge #2 (aka `nr_1`)
 * @param rresp2 Reader response #2 (aka `ar_1`)
 * @returns {bigint}
 */
export const recovery32 = (uid: number, chal: number, rchal: number, rresp: number, chal2: number, rchal2: number, rresp2: number): bigint => {
    const cd: Crapto1 = new Crapto1();
    cd.uid = uid;
    cd.chal = chal;
    cd.rchal = rchal;
    cd.rresp = rresp;
    cd.chal2 = chal2;
    cd.rchal2 = rchal2;
    cd.rresp2 = rresp2;
    cd.key = -1n;
    cd.RecoveryKey32();

    return cd.key
}