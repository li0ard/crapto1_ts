import { prng_successor } from "./crypto1";
import { LF_POLY_EVEN, LF_POLY_ODD, crypto1_word } from "./crypto1";
import { Crypto1State } from "./state";
import { bebit, binsearch, bit, evenParity32, evenParity8, extend_table, extend_table_simple, filter, parity, quicksort } from "./utils";

/**
 * Rollback the shift register in order to get previous states (for bits)
 * @param s State
 * @param input Input bit
 * @param isEncrypted Is input bit encrypted?
 * @returns {number} LFSR output bit
 */
export const lfsr_rollback_bit = (s: Crypto1State, input: number, isEncrypted: boolean = false): number => {
    let ret: number;
    let t: number;
    s.odd &= 0xffffff;
    t = s.odd;
    s.odd = s.even;
    s.even = t;
    let out = s.even & 1;
    out ^= LF_POLY_EVEN & (s.even >>= 1);
    out ^= LF_POLY_ODD & s.odd;
    out ^= (input !== 0) ? 1 : 0;
    out ^= (ret = s.peekCrypto1Bit) & ((isEncrypted) ? 1 : 0);
    s.even |= parity(out) << 23;
    return ret;
}

/**
 * Rollback the shift register in order to get previous states (for bytes)
 * @param s State
 * @param input Input byte
 * @param isEncrypted Is input byte encrypted?
 * @returns {number} LFSR output byte
 */
export const lfsr_rollback_byte = (s: Crypto1State, input: number, isEncrypted: boolean = false): number => {
    let ret: number = 0;
    for (let i = 7; i >= 0; --i) {
        ret |= lfsr_rollback_bit(s, bit(input, i), isEncrypted) << i;
    }
    return ret;
}

/**
 * Rollback the shift register in order to get previous states (for words (uint32))
 * @param s State
 * @param input Input word
 * @param isEncrypted Is input word encrypted?
 * @returns {number} LFSR output word
 */
export const lfsr_rollback_word = (s: Crypto1State, input: number, isEncrypted: boolean = false): number => {
    let ret: number = 0;
    for (let i = 31; i >= 0; --i) {
        ret |= lfsr_rollback_bit(s, bebit(input, i), isEncrypted) << (i ^ 24);
    }
    return ret;
}

/** Recursively narrow down the search space, 4 bits of keystream at a time */
const recover = (odd: number[], o_head: number, o_tail: number, oks: number, even: number[], e_head: number, e_tail: number, eks: number, rem: number, sl: Crypto1State[], s: number, input: number): number => {
    let o: number, e: number, i: number;
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
    for (i = 0; (i < 4) && (rem-- !== 0); i++) {
        oks >>>= 1;
        eks >>>= 1;
        input >>>= 2;
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
        } else if ((odd[o_tail] ^ 0x80000000) > (even[e_tail] ^ 0x80000000)) {
            o_tail = binsearch(odd, o_head, o_tail) - 1;
        } else {
            e_tail = binsearch(even, e_head, e_tail) - 1;
        }
    }
    return s;
}

/**
 * Recovery possible states from keystream from two's partial auth's
 * @param ks2 Keystream (32 -> 63)
 * @param input Value that was fed into lfsr at time keystream was generated
 * @returns {Crypto1State[]}
 */
export const lfsr_recovery32 = (ks2: number, input: number): Crypto1State[] => {
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

    input = (input >>> 16 & 0xff) | (input << 16) | (input & 0xff00);
    recover(odd, odd_head, odd_tail, oks, even, even_head, even_tail, eks, 11, statelist, 0, input << 1);
    return statelist;
}

/**
 * Recovery possible states from keystreams from one full auth
 * @param ks2 Keystream (32 -> 63)
 * @param ks3 Keystream (64 -> 95)
 * @returns {Crypto1State[]}
 */
export const lfsr_recovery64 = (ks2: number, ks3: number): Crypto1State[] => {
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

    let oks: number[] = Array(32).fill(0);
    let eks: number[] = Array(32).fill(0);
    let hi: number[] = Array(32).fill(0);
    let win = 0;
    let low = 0
    let table: number[] = Array(1 << 16).fill(0)
    let statelist: Crypto1State[] = []

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

        for (let j = 1; tail >= 0 && j < 29; j++) {
            tail = extend_table_simple(table, tail, oks[j]);
        }
        
        if (tail < 0) continue;

        for (let j = 0; j < 19; ++j) {
            low = low << 1 | evenParity32(i & S1[j]);
        }
        

        for (let j = 0; j < 32; ++j) {
            hi[j] = evenParity32(i & T1[j]);
        }
        
        for (; tail >= 0; --tail) {
            let needContinue = false
            for (let j = 0; j < 3; j++) {
                table[tail] = table[tail] << 1;
                table[tail] |= evenParity32((i & C1[j]) ^ (table[tail] & C2[j]));

                if(filter(table[tail]) != oks[29 + j]) {
                    needContinue = true
                    break
                }
            }

            if (needContinue) continue;

            for (let j = 0; j < 19; j++) {
                win = win << 1 | evenParity32(table[tail] & S2[j]);
            }

            win ^= low;
            for (let j = 0; j < 32; ++j) {
                win = win << 1 ^ hi[j] ^ evenParity32(table[tail] & T2[j]);
                if (filter(win) != eks[j]) {
                    needContinue = true
                    break
                }
            }

            if (needContinue) continue;

            table[tail] = table[tail] << 1 | evenParity32(LF_POLY_EVEN & table[tail]);
            statelist.push(new Crypto1State(
                table[tail] ^ evenParity32(LF_POLY_ODD & win),
                win
            ))
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
        lfsr_rollback_word(s[t], 0, false);
        lfsr_rollback_word(s[t], rchal, true);
        lfsr_rollback_word(s[t], uid ^ chal, false);
        let key = s[t].lfsr
        crypto1_word(s[t], uid ^ chal2, false);
        crypto1_word(s[t], rchal2, true);
        if (rresp2 === (crypto1_word(s[t], 0, false) ^ prng_successor(chal2, 64))) {
            return key;
        }
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
    let ks2 = rresp ^ prng_successor(chal, 64);
    let ks3 = tresp ^ prng_successor(chal, 96);
    let s = lfsr_recovery64(ks2, ks3)[0]
    lfsr_rollback_word(s, 0)
    lfsr_rollback_word(s, 0)
    lfsr_rollback_word(s, rchal, true)
    lfsr_rollback_word(s, uid^chal)

    return s.lfsr
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
    let ar = prng_successor(chal, 64);
    let ks0 = enc_chal ^ chal;
    let ks2 = rresp ^ ar;

    let s = lfsr_recovery32(ks0, uid ^ chal);

    for (let t = 0; (s[t].odd !== 0) || (s[t].even !== 0); t++) {
        crypto1_word(s[t], rchal, true);
        if(ks2 == crypto1_word(s[t], 0)) {
            lfsr_rollback_word(s[t], 0);
            lfsr_rollback_word(s[t], rchal, true);
            lfsr_rollback_word(s[t], uid ^ chal);
            return s[t].lfsr
        }
    }

    return -1n;
}

const nestedRecoverState = (uid: number, atks: Array<{ ntp: number, ks1: number }>): bigint[] => {
    const keyCnt = new Map<bigint, number>()
    for (const { ntp, ks1 } of atks) {
        const states = lfsr_recovery32(ks1, ntp ^ uid)
        for (const state of states) {
            lfsr_rollback_word(state, ntp ^ uid)
            const key = state.lfsr
            keyCnt.set(key, (keyCnt.get(key) ?? 0) + 1)
        }
    }

    return Array.from(keyCnt.entries()).sort((a, b) => b[1] - a[1]).slice(0, 50).map(([key]) => key);
}

const nestedIsValidNonce = (nt1: number, nt2: number, ks1: number, par: number): boolean => {
    if (evenParity8((nt1 >>> 24) & 0xFF) !== (bit(par, 0) ^ evenParity8((nt2 >>> 24) & 0xFF) ^ bit(ks1, 16))) return false
    if (evenParity8((nt1 >>> 16) & 0xFF) !== (bit(par, 1) ^ evenParity8((nt2 >>> 16) & 0xFF) ^ bit(ks1, 8))) return false
    if (evenParity8((nt1 >>> 8) & 0xFF) !== (bit(par, 2) ^ evenParity8((nt2 >>> 8) & 0xFF) ^ bit(ks1, 0))) return false
    return true
}

/**
 * Recover key from tags with static nonce
 * @param uid UID
 * @param keyType Key type (`0x60` - Key A; `0x61` - Key B)
 * @param atks Nonce logs of authentication
 * @returns {bigint[]} Candidates keys
 */
export const staticNestedAttack = (uid: number, keyType: 0x60 | 0x61, atks: Array<{ nt1: number, nt2: number }>): bigint[] => {
    let dist = 0
    if (atks[0].nt1 === 0x01200145) dist = 160;
    else if (atks[0].nt1 === 0x009080A2) dist = keyType === 0x60 ? 160 : 161;
    if (dist === 0) throw new Error('unknown static nonce');

    return nestedRecoverState(uid, atks.map(i => {
        const ntp = prng_successor(i.nt1, dist)
        const ks1 = i.nt2 ^ ntp

        dist += 160
        return { ntp, ks1 }
    }))
}

/**
 * Recover key from ags with weak PRNG
 * @param uid UID
 * @param dist Nonce distance between two authentication
 * @param atks Logs of nested attack
 * @returns {bigint[]} Candidates keys
 */
export const nestedAttack = (uid: number, dist: number, atks: Array<{ nt1: number, nt2: number, par: number }>): bigint[] => {
    const atks2: Array<{ ntp: number, ks1: number }> = []
    for (let i = 0; i < atks.length; i++) {
        const tmp = atks[i]
        const [nt1, nt2, par] = [tmp.nt1, tmp.nt2, tmp.par]
        let ntp = prng_successor(nt1, dist - 14)
        for (let j = 0; j < 29; j++, ntp = prng_successor(ntp, 1)) {
            const ks1 = (nt2 ^ ntp)
            if (nestedIsValidNonce(ntp, nt2, ks1, par)) atks2.push({ ntp, ks1 })
        }
    }

    return nestedRecoverState(uid, atks2)
}