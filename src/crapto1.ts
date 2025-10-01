import { Crypto1State, prng_successor, LF_POLY_EVEN, LF_POLY_ODD, bebit, binsearch, evenParity32, extend_table, extend_table_simple, filter, parity, quicksort, C1, C2, S1, S2, T1, T2, fastfwd, bit } from "./index";

/** Recursively narrow down the search space, 4 bits of keystream at a time */
const recover = (odd: number[], o_head: number, o_tail: number, oks: number, even: number[], e_head: number, e_tail: number, eks: number, rem: number, sl: Crypto1State[], s: number, input: number): number => {
    let o: number, e: number;
    if (rem === -1) {
        for (e = e_head; e <= e_tail; ++e) {
            even[e] = even[e] << 1 ^ parity(even[e] & LF_POLY_EVEN) ^ (((input & 4) !== 0) ? 1 : 0);
            for (o = o_head; o <= o_tail; ++o, ++s) {
                sl[s].even = odd[o];
                sl[s].odd = even[e] ^ parity(odd[o] & LF_POLY_ODD);
                sl[s + 1].odd = sl[s + 1].even = 0;
            }
        }
        return s;
    }
    for (let i = 0; (i < 4) && (rem-- !== 0); i++) {
        oks >>>= 1; eks >>>= 1; input >>>= 2;
        o_tail = extend_table(odd, o_head, o_tail, oks & 1, LF_POLY_EVEN << 1 | 1, LF_POLY_ODD << 1, 0);
        if (o_head > o_tail) return s;
        e_tail = extend_table(even, e_head, e_tail, eks & 1, LF_POLY_ODD, LF_POLY_EVEN << 1 | 1, input & 3);
        if (e_head > e_tail) return s;
    }
    quicksort(odd, o_head, o_tail);
    quicksort(even, e_head, e_tail);
    while (o_tail >= o_head && e_tail >= e_head) {
        if (((odd[o_tail] ^ even[e_tail]) >>> 24) === 0) {
            o_tail = binsearch(odd, o_head, o = o_tail);
            e_tail = binsearch(even, e_head, e = e_tail);
            s = recover(odd, o_tail--, o, oks, even, e_tail--, e, eks, rem, sl, s, input);
        }
        else if ((odd[o_tail] ^ 0x80000000) > (even[e_tail] ^ 0x80000000)) o_tail = binsearch(odd, o_head, o_tail) - 1;
        else e_tail = binsearch(even, e_head, e_tail) - 1;
    }
    return s;
}

/**
 * Recovery possible states from keystream from two's partial auth's
 * @param ks2 Keystream (32 -> 63)
 * @param input Value that was fed into lfsr at time keystream was generated
 */
export const lfsr_recovery32 = (ks2: number, input: number): Crypto1State[] => {
    const statelist: Crypto1State[] = Array.from({ length: 262144 }, () => new Crypto1State());
    const odd: number[] = Array(2097152).fill(0);
    const even: number[] = Array(2097152).fill(0);
    let stl: number = 0;
    let odd_head: number = 0, odd_tail: number = -1, oks: number = 0;
    let even_head: number = 0, even_tail: number = -1, eks: number = 0;

    for (let i = 31; i >= 0; i -= 2) oks = oks << 1 | bebit(ks2, i);
    for (let i = 30; i >= 0; i -= 2) eks = eks << 1 | bebit(ks2, i);

    statelist[stl].odd = statelist[stl].even = 0;

    for (let i = 1048576; i >= 0; --i) {
        if (filter(i) === (oks & 1)) odd[++odd_tail] = i;
        if (filter(i) === (eks & 1)) even[++even_tail] = i;
    }

    for (let i = 0; i < 4; i++) {
        odd_tail = extend_table_simple(odd, odd_tail, (oks >>>= 1) & 1);
        even_tail = extend_table_simple(even, even_tail, (eks >>>= 1) & 1);
    }

    input = (input >>> 16 & 0xff) | (input << 16) | (input & 0xff00);
    recover(odd, odd_head, odd_tail, oks, even, even_head, even_tail, eks, 11, statelist, 0, input << 1);
    return statelist;
}

/**
 * Recovery possible states from keystreams from one full auth
 * @param ks2 Keystream (32 -> 63)
 * @param ks3 Keystream (64 -> 95)
 */
export const lfsr_recovery64 = (ks2: number, ks3: number): Crypto1State[] => {
    const oks: number[] = Array(32).fill(0);
    const eks: number[] = Array(32).fill(0);
    const hi: number[] = Array(32).fill(0);
    const table: number[] = Array(65536).fill(0);
    const statelist: Crypto1State[] = [];
    let win = 0, low = 0;

    for (let i = 30; i >= 0; i -= 2) {
        oks[i >> 1] = bebit(ks2, i);
        oks[16 + (i >> 1)] = bebit(ks3, i);
    }

    for (let i = 31; i >= 0; i -= 2) {
        eks[i >> 1] = bebit(ks2, i);
        eks[16 + (i >> 1)] = bebit(ks3, i);
    }
    
    for (let i = 0xfffff; i >= 0; i--) {
        if (filter(i) != oks[0]) continue;

        let tail = 0;
        table[tail] = i;

        for (let j = 1; tail >= 0 && j < 29; j++) tail = extend_table_simple(table, tail, oks[j]);
        
        if (tail < 0) continue;
        for (let j = 0; j < 19; ++j) low = low << 1 | evenParity32(i & S1[j]);
        for (let j = 0; j < 32; ++j) hi[j] = evenParity32(i & T1[j]);
        
        for (; tail >= 0; --tail) {
            let needContinue = false;
            for (let j = 0; j < 3; j++) {
                table[tail] = table[tail] << 1;
                table[tail] |= evenParity32((i & C1[j]) ^ (table[tail] & C2[j]));

                if(filter(table[tail]) != oks[29 + j]) { needContinue = true; break; }
            }

            if (needContinue) continue;

            for (let j = 0; j < 19; j++) win = win << 1 | evenParity32(table[tail] & S2[j]);
            win ^= low;
            for (let j = 0; j < 32; ++j) {
                win = win << 1 ^ hi[j] ^ evenParity32(table[tail] & T2[j]);
                if (filter(win) != eks[j]) { needContinue = true; break; }
            }

            if (needContinue) continue;

            table[tail] = table[tail] << 1 | evenParity32(LF_POLY_EVEN & table[tail]);
            statelist.push(new Crypto1State(table[tail] ^ evenParity32(LF_POLY_ODD & win), win));
        }
    }

    return statelist;
}

/**
 * Recovery by two sets of 32 bit keystream authentication
 * @param uid UID
 * @param chal Tag challenge #1 (aka `nt`)
 * @param rchal Reader challenge #1 (aka `{nr_0}`)
 * @param rresp Reader response #1 (aka `{ar_0}`)
 * @param chal2 Tag challenge #2 (aka `nt1`)
 * @param rchal2 Reader challenge #2 (aka `{nr_1}`)
 * @param rresp2 Reader response #2 (aka `{ar_1}`)
 * @returns {bigint}
 */
export const recovery32 = (uid: number, chal: number, rchal: number, rresp: number, chal2: number, rchal2: number, rresp2: number): bigint => {
    const s = lfsr_recovery32(rresp ^ prng_successor(chal, 64), 0);
    for (let t = 0; (s[t].odd !== 0) || (s[t].even !== 0); ++t) {
        s[t].rollback_word();
        s[t].rollback_word(rchal, true);
        s[t].rollback_word(uid ^ chal);
        const key = s[t].lfsr;
        s[t].word(uid ^ chal2);
        s[t].word(rchal2, true);
        if (rresp2 === (s[t].word() ^ prng_successor(chal2, 64))) return key;
    }
    return -1n;
}

/**
 * Recovery by one set of full 64 bit keystream authentication
 * @param uid UID
 * @param chal Tag challenge (aka `nt`)
 * @param rchal Reader challenge (aka `{nr}`)
 * @param rresp Reader response (aka `{ar}`)
 * @param tresp Tag response (aka `{at}`)
 * @returns {bigint}
 */
export const recovery64 = (uid: number, chal: number, rchal: number, rresp: number, tresp: number): bigint => {
    const ks2 = rresp ^ prng_successor(chal, 64);
    const ks3 = tresp ^ prng_successor(chal, 96);
    const s = lfsr_recovery64(ks2, ks3)[0];
    s.rollback_word();
    s.rollback_word();
    s.rollback_word(rchal, true);
    s.rollback_word(uid^chal);

    return s.lfsr;
}

/**
 * Recovery by partial nested authentication
 * 
 * @author doegox
 * @param uid UID
 * @param chal Tag challenge (aka `nt`)
 * @param enc_chal Encrypted tag challenge (aka `{nt}`)
 * @param rchal Reader challenge (aka `{nr}`)
 * @param rresp Reader response (aka `{ar}`)
 * @returns {bigint}
 */
export const recoveryNested = (uid: number, chal: number, enc_chal: number, rchal: number, rresp: number): bigint => {
    const ar = prng_successor(chal, 64);
    const ks0 = enc_chal ^ chal;
    const ks2 = rresp ^ ar;
    const s = lfsr_recovery32(ks0, uid ^ chal);

    for (let t = 0; (s[t].odd !== 0) || (s[t].even !== 0); t++) {
        s[t].word(rchal, true);
        if(ks2 == s[t].word()) {
            s[t].rollback_word();
            s[t].rollback_word(rchal, true);
            s[t].rollback_word(uid ^ chal);
            return s[t].lfsr;
        }
    }

    return -1n;
}

const lfsr_prefix_ks = (ks: number[], isOdd: boolean): number[] => {
    const candidates: number[] = [];
    for (let i = 0; i < 2097152; i++) {
        let isCandidate = true;
        for (let j = 0; isCandidate && j < 8; j++) {
            const tmp = (i ^ fastfwd[isOdd ? (8 + j) : j]) >>> 0;
            isCandidate = bit(ks[j], isOdd ? 1 : 0) === filter(tmp >>> 1) && bit(ks[j], isOdd ? 3 : 2) === filter(tmp);
        }
        if (isCandidate) candidates.push(i);
    }
    
    return candidates;
}

/** Helper which eliminates possible states using parity */
const check_pfx_parity = (pfx: number, ar: number, par: number[][], odd: number, even: number, isZeroPar: boolean): Crypto1State | null => {
    const state = new Crypto1State();
    for (let i = 0; i < 8; i++) {
        [state.odd, state.even] = [(odd ^ fastfwd[8 + i]) >>> 0, (even ^ fastfwd[i]) >>> 0];
        state.rollback_bit();
        state.rollback_bit();
        const ks3 = state.rollback_bit();
        const ks2 = state.rollback_word();
        const ks1 = state.rollback_word(pfx | (i << 5), true);
        if (isZeroPar) return state;

        const nr = (ks1 ^ (pfx | (i << 5))) >>> 0;
        const arEnc = (ks2 ^ ar) >>> 0;

        if ((evenParity32(nr & 0x000000FF) ^ par[i][3] ^ bit(ks2, 24)) < 1) return null;
        if ((evenParity32(arEnc & 0xFF000000) ^ par[i][4] ^ bit(ks2, 16)) < 1) return null;
        if ((evenParity32(arEnc & 0x00FF0000) ^ par[i][5] ^ bit(ks2, 8)) < 1) return null;
        if ((evenParity32(arEnc & 0x0000FF00) ^ par[i][6] ^ bit(ks2, 0)) < 1) return null;
        if ((evenParity32(arEnc & 0x000000FF) ^ par[i][7] ^ ks3) < 1) return null;
    }
    return state;
}

export const lfsr_common_prefix = (pfx: number, ar: number, ks: number[], par: number[][], isZeroPar: boolean): Crypto1State[] => {
    const odds = lfsr_prefix_ks(ks, true);
    const evens = lfsr_prefix_ks(ks, false);
    const states: Crypto1State[] = [];
    for (let odd of odds) {
        for (let even of evens) {
            for (let i = 0; i < 64; i++) {
                odd += 2097152;
                even += (i & 0x7) > 0 ? 2097152 : 4194304;
                const tmp = check_pfx_parity(pfx, ar, par, odd, even, isZeroPar);
                if(tmp !== null) states.push(tmp);
            }
        }
    }

    return states;
}