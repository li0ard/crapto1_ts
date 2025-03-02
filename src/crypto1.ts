import { Crypto1State } from "./state";
import { bebit, bit, filter, oddParity8, parity, swapendian } from "./utils";

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
 * Generate keystream for words (uint32)
 * @param s State
 * @param input Input word
 * @param isEncrypted Is input word encrypted?
 * @returns {number}
 */
export const crypto1_word = (s: Crypto1State, input: number, isEncrypted: boolean = false): number => {
    let i: number, ret: number = 0;
    for (i = 0; i < 32; ++i) {
        ret |= crypto1_bit(s, bebit(input, i), isEncrypted) << (i ^ 24);
    }
    return ret;
}

/**
 * Generate keystream for bytes
 * @param s State
 * @param input Input byte
 * @param isEncrypted Is input byte encrypted?
 * @returns {number}
 */
export const crypto1_byte = (s: Crypto1State, input: number, isEncrypted: boolean = false): number => {
    let i: number, ret: number = 0;
    for (i = 0; i < 8; ++i) {
        ret |= crypto1_bit(s, bit(input, i), isEncrypted) << i;
    }
    return ret;
}

/**
 * Generate keystream for bits
 * @param s State
 * @param input Input bit
 * @param isEncrypted Is input bit encrypted?
 * @returns {number}
 */
export const crypto1_bit = (s: Crypto1State, input: number, isEncrypted: boolean = false): number => {
    let feedin: number;
    let ret: number = filter(s.odd);
    feedin = ret & ((isEncrypted) ? 1 : 0);
    feedin ^= ((input !== 0) ? 1 : 0);
    feedin ^= LF_POLY_ODD & s.odd;
    feedin ^= LF_POLY_EVEN & s.even;
    s.even = s.even << 1 | parity(feedin);
    s.odd ^= s.even;
    s.even ^= s.odd;
    s.odd ^= s.even;
    return ret;
}

/**
 * Proceed encryption/decryption process
 * @param s State
 * @param data Input data
 * @param isIn Use input data as input word for keystream generation?
 * @returns {number[]}
 */
export const encrypt = (s: Crypto1State, data: number[], isIn: boolean = false): number[] => {
    let result: number[] = []
    for (let i = 0; i < data.length; i++) {
        result[i] = data[i] ^ crypto1_byte(s, isIn ? data[i] : 0);
    }

    return result
}