import { LF_POLY_EVEN, LF_POLY_ODD, bebit, bit, filter, parity } from "./index";
import { bitBigInt } from "./utils";

/** Crypto1 state */
export class Crypto1State {
    constructor(public odd: number = 0, public even: number = 0) {}
    
    /**
     * Initialize state from key (aka LFSR value)
     * @param key 
     * @returns 
     */
    static fromKey(key: bigint): Crypto1State {
        let odd = 0n;
        let even = 0n;

        for (let i = 47; i > 0; i -= 2) {
            odd = odd << 1n | bitBigInt(key, (i - 1) ^ 7);
            even = even << 1n | bitBigInt(key, i ^ 7);
        }
        return new Crypto1State(Number(odd), Number(even));
    }

    /** Get LFSR value (aka Key) */
    get lfsr(): bigint {
        let lfsr = 0n;
        for (let i = 23; i >= 0; --i) {
            lfsr = lfsr << 1n | BigInt(bit(this.odd, i ^ 3));
            lfsr = lfsr << 1n | BigInt(bit(this.even, i ^ 3));
        }
        return lfsr;
    }

    /** Get filtered state `odd` value */
    get peekCrypto1Bit(): number { return filter(this.odd); }

    /**
     * Generate keystream (bit)
     * @param input Input bit
     * @param isEncrypted Is input bit encrypted?
     */
    bit(input: number = 0, isEncrypted: boolean = false): number {
        let ret: number = this.peekCrypto1Bit;
        let feedin = ret & ((isEncrypted) ? 1 : 0);
        feedin ^= ((input !== 0) ? 1 : 0);
        feedin ^= LF_POLY_ODD & this.odd;
        feedin ^= LF_POLY_EVEN & this.even;
        this.even = this.even << 1 | parity(feedin);
        this.odd ^= this.even;
        this.even ^= this.odd;
        this.odd ^= this.even;
        return ret;
    }

    /**
     * Generate keystream (byte)
     * @param input Input byte
     * @param isEncrypted Is input byte encrypted?
     */
    byte(input: number = 0, isEncrypted: boolean = false): number {
        let ret: number = 0;
        //for (let i = 0; i < 8; ++i) ret |= crypto1_bit(s, bit(input, i), isEncrypted) << i;
        ret |= this.bit(bit(input, 0), isEncrypted) << 0;
        ret |= this.bit(bit(input, 1), isEncrypted) << 1;
        ret |= this.bit(bit(input, 2), isEncrypted) << 2;
        ret |= this.bit(bit(input, 3), isEncrypted) << 3;
        ret |= this.bit(bit(input, 4), isEncrypted) << 4;
        ret |= this.bit(bit(input, 5), isEncrypted) << 5;
        ret |= this.bit(bit(input, 6), isEncrypted) << 6;
        ret |= this.bit(bit(input, 7), isEncrypted) << 7;
        return ret;
    }

    /**
     * Generate keystream (word)
     * @param input Input word (uint32)
     * @param isEncrypted Is input word encrypted?
     */
    word(input: number = 0, isEncrypted: boolean = false): number {
        let ret: number = 0;
        //for (let i = 0; i < 32; ++i) ret |= crypto1_bit(s, bebit(input, i), isEncrypted) << (i ^ 24);
        ret |= this.bit(bebit(input, 0), isEncrypted) << 24;
        ret |= this.bit(bebit(input, 1), isEncrypted) << 25;
        ret |= this.bit(bebit(input, 2), isEncrypted) << 26;
        ret |= this.bit(bebit(input, 3), isEncrypted) << 27;
        ret |= this.bit(bebit(input, 4), isEncrypted) << 28;
        ret |= this.bit(bebit(input, 5), isEncrypted) << 29;
        ret |= this.bit(bebit(input, 6), isEncrypted) << 30;
        ret |= this.bit(bebit(input, 7), isEncrypted) << 31;
        ret |= this.bit(bebit(input, 8), isEncrypted) << 16;
        ret |= this.bit(bebit(input, 9), isEncrypted) << 17;
        ret |= this.bit(bebit(input, 10), isEncrypted) << 18;
        ret |= this.bit(bebit(input, 11), isEncrypted) << 19;
        ret |= this.bit(bebit(input, 12), isEncrypted) << 20;
        ret |= this.bit(bebit(input, 13), isEncrypted) << 21;
        ret |= this.bit(bebit(input, 14), isEncrypted) << 22;
        ret |= this.bit(bebit(input, 15), isEncrypted) << 23;
        ret |= this.bit(bebit(input, 16), isEncrypted) << 8;
        ret |= this.bit(bebit(input, 17), isEncrypted) << 9;
        ret |= this.bit(bebit(input, 18), isEncrypted) << 10;
        ret |= this.bit(bebit(input, 19), isEncrypted) << 11;
        ret |= this.bit(bebit(input, 20), isEncrypted) << 12;
        ret |= this.bit(bebit(input, 21), isEncrypted) << 13;
        ret |= this.bit(bebit(input, 22), isEncrypted) << 14;
        ret |= this.bit(bebit(input, 23), isEncrypted) << 15;
        ret |= this.bit(bebit(input, 24), isEncrypted) << 0;
        ret |= this.bit(bebit(input, 25), isEncrypted) << 1;
        ret |= this.bit(bebit(input, 26), isEncrypted) << 2;
        ret |= this.bit(bebit(input, 27), isEncrypted) << 3;
        ret |= this.bit(bebit(input, 28), isEncrypted) << 4;
        ret |= this.bit(bebit(input, 29), isEncrypted) << 5;
        ret |= this.bit(bebit(input, 30), isEncrypted) << 6;
        ret |= this.bit(bebit(input, 31), isEncrypted) << 7;
        return ret;
    }

    /**
     * Proceed encryption/decryption process
     * @param data Input data
     * @param isIn Use input data as input word for keystream generation?
     */
    crypt(data: number[], isIn: boolean = false): number[] {
        const result: number[] = [];
        for (let i = 0; i < data.length; i++) result[i] = data[i] ^ this.byte(isIn ? data[i] : 0);
        return result;
    }

    /**
     * Rollback state (bit)
     * @param input Input bit
     * @param isEncrypted Is input bit encrypted?
     */
    rollback_bit(input: number = 0, isEncrypted: boolean = false): number {
        let ret: number;
        this.odd &= 0xffffff;
        const t = this.odd;
        this.odd = this.even;
        this.even = t;
        let out = this.even & 1;
        out ^= LF_POLY_EVEN & (this.even >>= 1);
        out ^= LF_POLY_ODD & this.odd;
        out ^= (input !== 0) ? 1 : 0;
        out ^= (ret = this.peekCrypto1Bit) & ((isEncrypted) ? 1 : 0);
        this.even |= parity(out) << 23;
        return ret;
    }

    /**
     * Rollback state (byte)
     * @param input Input byte
     * @param isEncrypted Is input byte encrypted?
     */
    rollback_byte(input: number = 0, isEncrypted: boolean = false): number {
        let ret: number = 0;
        //for (let i = 7; i >= 0; --i) ret |= this.rollback_bit(bit(input, i), isEncrypted) << i;
        ret |= this.rollback_bit(bit(input, 7), isEncrypted) << 7;
        ret |= this.rollback_bit(bit(input, 6), isEncrypted) << 6;
        ret |= this.rollback_bit(bit(input, 5), isEncrypted) << 5;
        ret |= this.rollback_bit(bit(input, 4), isEncrypted) << 4;
        ret |= this.rollback_bit(bit(input, 3), isEncrypted) << 3;
        ret |= this.rollback_bit(bit(input, 2), isEncrypted) << 2;
        ret |= this.rollback_bit(bit(input, 1), isEncrypted) << 1;
        ret |= this.rollback_bit(bit(input, 0), isEncrypted) << 0;
        return ret;
    }

    /**
     * Rollback state (word)
     * @param input Input word (uint32)
     * @param isEncrypted Is input word encrypted?
     */
    rollback_word(input: number = 0, isEncrypted: boolean = false): number {
        let ret: number = 0;
        //for (let i = 31; i >= 0; --i) ret |= this.rollback_bit(bebit(input, i), isEncrypted) << (i ^ 24);
        ret |= this.rollback_bit(bebit(input, 31), isEncrypted) << 7;
        ret |= this.rollback_bit(bebit(input, 30), isEncrypted) << 6;
        ret |= this.rollback_bit(bebit(input, 29), isEncrypted) << 5;
        ret |= this.rollback_bit(bebit(input, 28), isEncrypted) << 4;
        ret |= this.rollback_bit(bebit(input, 27), isEncrypted) << 3;
        ret |= this.rollback_bit(bebit(input, 26), isEncrypted) << 2;
        ret |= this.rollback_bit(bebit(input, 25), isEncrypted) << 1;
        ret |= this.rollback_bit(bebit(input, 24), isEncrypted) << 0;
        ret |= this.rollback_bit(bebit(input, 23), isEncrypted) << 15;
        ret |= this.rollback_bit(bebit(input, 22), isEncrypted) << 14;
        ret |= this.rollback_bit(bebit(input, 21), isEncrypted) << 13;
        ret |= this.rollback_bit(bebit(input, 20), isEncrypted) << 12;
        ret |= this.rollback_bit(bebit(input, 19), isEncrypted) << 11;
        ret |= this.rollback_bit(bebit(input, 18), isEncrypted) << 10;
        ret |= this.rollback_bit(bebit(input, 17), isEncrypted) << 9;
        ret |= this.rollback_bit(bebit(input, 16), isEncrypted) << 8;
        ret |= this.rollback_bit(bebit(input, 15), isEncrypted) << 23;
        ret |= this.rollback_bit(bebit(input, 14), isEncrypted) << 22;
        ret |= this.rollback_bit(bebit(input, 13), isEncrypted) << 21;
        ret |= this.rollback_bit(bebit(input, 12), isEncrypted) << 20;
        ret |= this.rollback_bit(bebit(input, 11), isEncrypted) << 19;
        ret |= this.rollback_bit(bebit(input, 10), isEncrypted) << 18;
        ret |= this.rollback_bit(bebit(input, 9), isEncrypted) << 17;
        ret |= this.rollback_bit(bebit(input, 8), isEncrypted) << 16;
        ret |= this.rollback_bit(bebit(input, 7), isEncrypted) << 31;
        ret |= this.rollback_bit(bebit(input, 6), isEncrypted) << 30;
        ret |= this.rollback_bit(bebit(input, 5), isEncrypted) << 29;
        ret |= this.rollback_bit(bebit(input, 4), isEncrypted) << 28;
        ret |= this.rollback_bit(bebit(input, 3), isEncrypted) << 27;
        ret |= this.rollback_bit(bebit(input, 2), isEncrypted) << 26;
        ret |= this.rollback_bit(bebit(input, 1), isEncrypted) << 25;
        ret |= this.rollback_bit(bebit(input, 0), isEncrypted) << 24;
        return ret;
    }
}

export * from "./crapto1";
export * from "./utils";