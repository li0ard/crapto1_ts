import type { Crypto1State } from "./state";
import { bebit, filter, parity, swapendian } from "./utils";

export const LF_POLY_ODD: number = 0x29CE5C;
export const LF_POLY_EVEN: number = 0x870804;

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

/**
 * Proceed Crypto1 encryption/decryption process (for words (uint32))
 * @param s State
 * @param in_ Word
 * @param isEncrypted Encrypted?
 * @returns {number}
 */
export const crypto1_word = (s: Crypto1State, in_: number, isEncrypted: boolean = false): number => {
    let i: number, ret: number = 0;
    for (i = 0; i < 32; ++i) {
        ret |= crypto1_bit(s, bebit(in_, i), isEncrypted) << (i ^ 24);
    }
    return ret;
}

/**
 * Proceed Crypto1 encryption/decryption process (for bits)
 * @param s State
 * @param in_ Bit
 * @param isEncrypted Encrypted?
 * @returns {number}
 */
export const crypto1_bit = (s: Crypto1State, in_: number, isEncrypted: boolean = false): number => {
    let feedin: number;
    let ret: number = filter(s.odd);
    feedin = ret & ((isEncrypted) ? 1 : 0);
    feedin ^= ((in_ !== 0) ? 1 : 0);
    feedin ^= LF_POLY_ODD & s.odd;
    feedin ^= LF_POLY_EVEN & s.even;
    s.even = s.even << 1 | parity(feedin);
    s.odd ^= s.even;
    s.even ^= s.odd;
    s.odd ^= s.even;
    return ret;
}