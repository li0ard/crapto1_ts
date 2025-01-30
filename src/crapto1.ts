import { bebit, binsearch, bit, evenParity32, extend_table, extend_table_simple, filter, parity, quicksort } from "./utils";

/**
 * Swaps endianness of given number
 * @param x Number to swap
 * @returns {number}
 */
const swapendian = (x: number): number => {
    x = (x >>> 8 & 0xff00ff) | (x & 0xff00ff) << 8;
    x = x >>> 16 | x << 16;
    return x;
}

/**
 * Helper used to obscure the keystream during authentication
 * @param x Input data
 * @param n Keystream number
 * @returns {number}
 */
export const prng_successor = (x: number, n: number): number => {
    x = swapendian(x);
    while ((n--) > 0) {
        x = x >>> 1 | (x >>> 16 ^ x >>> 18 ^ x >>> 19 ^ x >>> 21) << 31;
    }
    return swapendian(x);
}

/** Crypto-1 state class */
class Crypto1State {
    odd: number = 0;
    even: number = 0;
}

export class Crapto1 {
    key: bigint = -1n;

    filterlut: Uint8Array = new Uint8Array(1 << 20);
    LF_POLY_ODD: number = 0x29CE5C;
    LF_POLY_EVEN: number = 0x870804;

    constructor() {
        for (let i = 0; i < 1 << 20; ++i) {
            this.filterlut[i] = filter(i);
        }
    }

    lfsr_recovery32(ks2: number, in_: number): Crypto1State[] {
        const statelist: Crypto1State[] = Array.from({ length: 1 << 18 }, () => new Crypto1State());
        let stl: number = 0;
        const odd: number[] = Array(1 << 21).fill(0);
        const even: number[] = Array(1 << 21).fill(0);
        let odd_head: number = 0, odd_tail: number = -1, oks: number = 0;
        let even_head: number = 0, even_tail: number = -1, eks: number = 0;

        for (let i = 31; i >= 0; i -= 2) {
            oks = oks << 1 | bebit(ks2, i);
        }
        for (let i = 30; i >= 0; i -= 2) {
            eks = eks << 1 | bebit(ks2, i);
        }

        statelist[stl].odd = statelist[stl].even = 0;

        for (let i = 1 << 20; i >= 0; --i) {
            if (filter(i) === (oks & 1)) {
                odd[++odd_tail] = i;
            }
            if (filter(i) === (eks & 1)) {
                even[++even_tail] = i;
            }
        }

        for (let i = 0; i < 4; i++) {
            odd_tail = extend_table_simple(odd, odd_tail, (oks >>>= 1) & 1);
            even_tail = extend_table_simple(even, even_tail, (eks >>>= 1) & 1);
        }

        in_ = (in_ >>> 16 & 0xff) | (in_ << 16) | (in_ & 0xff00);
        this.recover(odd, odd_head, odd_tail, oks, even, even_head, even_tail, eks, 11, statelist, 0, in_ << 1);
        return statelist;
    }

    lfsr_recovery64(ks2: number, ks3: number) {
        let oks: number[] = Array(32).fill(0);
        let eks: number[] = Array(32).fill(0);
        let hi: number[] = Array(32).fill(0);
        let low = 0;
        let win = 0;
        let table: number[] = Array(1 << 16).fill(0);
        let statelist: Crypto1State[] = []

        const S1: Readonly<number[]> = [0x62141, 0x310A0, 0x18850, 0x0C428, 0x06214, 0x0310A,
            0x85E30, 0xC69AD, 0x634D6, 0xB5CDE, 0xDE8DA, 0x6F46D,
            0xB3C83, 0x59E41, 0xA8995,  0xD027F, 0x6813F, 0x3409F, 0x9E6FA]

        const S2: Readonly<number[]> = [0x3A557B00, 0x5D2ABD80, 0x2E955EC0, 0x174AAF60, 0x0BA557B0,
            0x05D2ABD8, 0x0449DE68, 0x048464B0, 0x42423258, 0x278192A8,
            0x156042D0, 0x0AB02168, 0x43F89B30, 0x61FC4D98, 0x765EAD48,
            0x7D8FDD20, 0x7EC7EE90, 0x7F63F748, 0x79117020]
        const T1: Readonly<number[]> = [0x4F37D, 0x279BE, 0x97A6A, 0x4BD35, 0x25E9A, 0x12F4D, 0x097A6, 0x80D66,
            0xC4006, 0x62003, 0xB56B4, 0x5AB5A, 0xA9318, 0xD0F39, 0x6879C, 0xB057B,
            0x582BD, 0x2C15E, 0x160AF, 0x8F6E2, 0xC3DC4, 0xE5857, 0x72C2B, 0x39615,
            0x98DBF, 0xC806A, 0xE0680, 0x70340, 0x381A0, 0x98665, 0x4C332, 0xA272C]
        
        const T2: Readonly<number[]> = [0x3C88B810, 0x5E445C08, 0x2982A580, 0x14C152C0, 0x4A60A960,
            0x253054B0, 0x52982A58, 0x2FEC9EA8, 0x1156C4D0, 0x08AB6268,
            0x42F53AB0, 0x217A9D58, 0x161DC528, 0x0DAE6910, 0x46D73488,
            0x25CB11C0, 0x52E588E0, 0x6972C470, 0x34B96238, 0x5CFC3A98,
            0x28DE96C8, 0x12CFC0E0, 0x4967E070, 0x64B3F038, 0x74F97398,
            0x7CDC3248, 0x38CE92A0, 0x1C674950, 0x0E33A4A8, 0x01B959D0,
            0x40DCACE8, 0x26CEDDF0]
        
        const C1: Readonly<number[]> = [0x846B5, 0x4235A, 0x211AD]
        const C2: Readonly<number[]> = [0x1A822E0, 0x21A822E0, 0x21A822E0]

        for (var i = 30; i >= 0; i -= 2) {
            oks[i >> 1] = bebit(ks2, i);
            oks[16 + (i >> 1)] = bebit(ks3, i);
        }
        

        for (var i = 31; i >= 0; i -= 2) {
            eks[i >> 1] = bebit(ks2, i);
            eks[16 + (i >> 1)] = bebit(ks3, i);
        }

        /*for (let i = 0xfffff; i >= 0; i--) {
            if (filter(i) !== oks[0]) continue;
            let tail = 0;
            table[tail] = i;

            for (let j = 1; tail >= 0 && j < 29; j++) {
                extend_table_simple(table, tail, oks[j]);
            }
            if (tail < 0) continue;

            for (let j = 0; j < 19; ++j) {
                low = (low << 1) | evenParity32(i & S1[j]);
            }
    
            for (let j = 0; j < 32; ++j) {
                hi[j] = evenParity32(i & T1[j]);
            }

            for (; tail >= 0; --tail) {
                for (let j = 0; j < 3; j++) {
                    table[tail] = (table[tail] << 1) | evenParity32((i & C1[j]) ^ (table[tail] & C2[j]));
                    if (filter(table[tail]) !== oks[29 + j]) {
                        continue;
                    }
                }

                for (let j = 0; j < 19; j++) {
                    win = (win << 1) | evenParity32(table[tail] & S2[j]);
                }
                win ^= low;

                for (let j = 0; j < 32; ++j) {
                    win = (win << 1) ^ hi[j] ^ evenParity32(table[tail] & T2[j]);
                    if (filter(win) !== eks[j]) {
                        continue;
                    }
                }    

                table[tail] = (table[tail] << 1) | evenParity32(this.LF_POLY_EVEN & table[tail]);

                const s = new Crypto1State();
                s.odd = table[tail] ^ evenParity32(this.LF_POLY_ODD & win),
                s.even = win
                statelist.push(s);
            }
        }*/
        /*for (var i = 0xfffff; i >= 0; i--) {
            if (filter(i) != oks[0]) {
                continue
            }

            var tail = 0;
            table[tail] = i;

            for (var j = 1; tail >= 0 && j < 29; j++) {
                extend_table_simple(table, tail, oks[j]);
            }
            if (tail < 0) {
                continue;
            }

            for (var j = 0; j < 19; ++j) {
                low = low << 1 | evenParity32(i & S1[j]);
            }

            for (var j = 0; j < 32; ++j) {
                hi[j] = evenParity32(i & T1[j]);
            }

            for (; tail >= 0; --tail) {
                let gotoContinue = false
                for (var j = 0; j < 3; j++) {
                    table[tail] = table[tail] << 1;
                    table[tail] |= evenParity32((i & C1[j]) ^ (table[tail] & C2[j]));
                    if (filter(table[tail]) != oks[29 + j]) {
                        gotoContinue = true
                        break;
                    }
                }
                if (gotoContinue) {
                    continue;
                }

                for (var j = 0; j < 19; j++) {
                    win = win << 1 | evenParity32(table[tail] & S2[j]);
                }

                win ^= low;
                for (var j = 0; j < 32; ++j) {
                    win = win << 1 ^ hi[j] ^ evenParity32(table[tail] & T2[j]);
                    if(filter(win) != eks[j]) {
                        gotoContinue = true
                        break;
                    }
                }
                if (gotoContinue) {
                    continue;
                }

                table[tail] = table[tail] << 1 | evenParity32(this.LF_POLY_EVEN & table[tail]);
                let s = new Crypto1State()
                s.odd = table[tail] ^ evenParity32(this.LF_POLY_ODD & win)
                s.even = win
                console.log(4)
                statelist.push(s)
            }
        }*/

        return statelist
    }

    /**
     * recursively narrow down the search space, 4 bits of keystream at a time
     * @param odd 
     * @param o_head 
     * @param o_tail 
     * @param oks 
     * @param even 
     * @param e_head 
     * @param e_tail 
     * @param eks 
     * @param rem 
     * @param sl 
     * @param s 
     * @param in_ 
     * @returns {number}
     */
    recover(odd: number[], o_head: number, o_tail: number, oks: number, even: number[], e_head: number, e_tail: number, eks: number, rem: number, sl: Crypto1State[], s: number, in_: number): number {
        let o: number, e: number, i: number;
        if (rem === -1) {
            for (e = e_head; e <= e_tail; ++e) {
                even[e] = even[e] << 1 ^ parity(even[e] & this.LF_POLY_EVEN) ^ (((in_ & 4) !== 0) ? 1 : 0);
                for (o = o_head; o <= o_tail; ++o, ++s) {
                    sl[s].even = odd[o];
                    sl[s].odd = even[e] ^ parity(odd[o] & this.LF_POLY_ODD);
                    sl[s + 1].odd = sl[s + 1].even = 0;
                }
            }
            return s;
        }
        for (i = 0; (i < 4) && (rem-- !== 0); i++) {
            oks >>>= 1;
            eks >>>= 1;
            in_ >>>= 2;
            o_tail = extend_table(odd, o_head, o_tail, oks & 1, this.LF_POLY_EVEN << 1 | 1, this.LF_POLY_ODD << 1, 0);
            if (o_head > o_tail) return s;
            e_tail = extend_table(even, e_head, e_tail, eks & 1, this.LF_POLY_ODD, this.LF_POLY_EVEN << 1 | 1, in_ & 3);
            if (e_head > e_tail) return s;
        }
        quicksort(odd, o_head, o_tail);
        quicksort(even, e_head, e_tail);
        while (o_tail >= o_head && e_tail >= e_head) {
            if (((odd[o_tail] ^ even[e_tail]) >>> 24) === 0) {
                o_tail = binsearch(odd, o_head, o = o_tail);
                e_tail = binsearch(even, e_head, e = e_tail);
                s = this.recover(odd, o_tail--, o, oks, even, e_tail--, e, eks, rem, sl, s, in_);
            } else if ((odd[o_tail] ^ 0x80000000) > (even[e_tail] ^ 0x80000000)) {
                o_tail = binsearch(odd, o_head, o_tail) - 1;
            } else {
                e_tail = binsearch(even, e_head, e_tail) - 1;
            }
        }
        return s;
    }

    /**
     * Rollback the shift register in order to get previous states
     * @param s State
     * @param in_ 
     * @param isEncrypted 
     * @returns {number}
     */
    lfsr_rollback_bit(s: Crypto1State, in_: number, isEncrypted: boolean = false): number {
        let ret: number;
        let t: number;
        s.odd &= 0xffffff;
        t = s.odd;
        s.odd = s.even;
        s.even = t;
        let out = s.even & 1;
        out ^= this.LF_POLY_EVEN & (s.even >>= 1);
        out ^= this.LF_POLY_ODD & s.odd;
        out ^= (in_ !== 0) ? 1 : 0;
        out ^= (ret = filter(s.odd)) & ((isEncrypted) ? 1 : 0);
        s.even |= parity(out) << 23;
        return ret;
    }

    lfsr_rollback_word(s: Crypto1State, in_: number, isEncrypted: boolean = false): number {
        let ret: number = 0;
        for (let i = 31; i >= 0; --i) {
            ret |= this.lfsr_rollback_bit(s, bebit(in_, i), isEncrypted) << (i ^ 24);
        }
        return ret;
    }

    crypto1_get_lfsr(state: Crypto1State): bigint {
        let i: number;
        let lfsr = 0n
        for (let i = 23; i >= 0; --i) {
            lfsr = lfsr << 1n | BigInt(bit(state.odd, i ^ 3));
            lfsr = lfsr << 1n | BigInt(bit(state.even, i ^ 3));
        }
        return lfsr;
    }

    crypto1_word(s: Crypto1State, in_: number, isEncrypted: boolean = false): number {
        let i: number, ret: number = 0;
        for (i = 0; i < 32; ++i) {
            ret |= this.crypto1_bit(s, bebit(in_, i), isEncrypted) << (i ^ 24);
        }
        return ret;
    }

    crypto1_bit(s: Crypto1State, in_: number, isEncrypted: boolean = false): number {
        let feedin: number;
        let ret: number = filter(s.odd);
        feedin = ret & ((isEncrypted) ? 1 : 0);
        feedin ^= ((in_ !== 0) ? 1 : 0);
        feedin ^= this.LF_POLY_ODD & s.odd;
        feedin ^= this.LF_POLY_EVEN & s.even;
        s.even = s.even << 1 | parity(feedin);
        s.odd ^= s.even;
        s.even ^= s.odd;
        s.odd ^= s.even;
        return ret;
    }

    RecoveryKey32(uid: number, chal: number, rchal: number, rresp: number, chal2: number, rchal2: number, rresp2: number): boolean {
        const s = this.lfsr_recovery32(rresp ^ prng_successor(chal, 64), 0);
        for (let t = 0; (s[t].odd !== 0) || (s[t].even !== 0); ++t) {
            this.lfsr_rollback_word(s[t], 0, false);
            this.lfsr_rollback_word(s[t], rchal, true);
            this.lfsr_rollback_word(s[t], uid ^ chal, false);
            this.key = this.crypto1_get_lfsr(s[t]);
            this.crypto1_word(s[t], uid ^ chal2, false);
            this.crypto1_word(s[t], rchal2, true);
            if (rresp2 === (this.crypto1_word(s[t], 0, false) ^ prng_successor(chal2, 64))) {
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
    cd.key = -1n;
    if(cd.RecoveryKey32(uid, chal, rchal, rresp, chal2, rchal2, rresp2)) {
        return cd.key
    }

    return -1n;
}