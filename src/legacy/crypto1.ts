import type { Crypto1State } from "./state";

export class Crypto1 {
    static readonly LF_POLY_ODD: number = 0x29CE5C;
    static readonly LF_POLY_EVEN: number = 0x870804;

    static crypto1Bit(state: Crypto1State, input: number = 0, isEncrypted: boolean = false): number {
        let feedin: number;
        let ret: number = this.filter(state.odd);

        feedin = ret & (isEncrypted ? 1 : 0);
        feedin ^= input !== 0 ? 1 : 0;
        feedin ^= this.LF_POLY_ODD & state.odd;
        feedin ^= this.LF_POLY_EVEN & state.even;
        state.even = (state.even << 1) | this.evenParity32(feedin);

        const x: number = state.odd;
        state.odd = state.even;
        state.even = x;

        return ret;
    }

    static crypto1Byte(state: Crypto1State, input: number = 0, isEncrypted: boolean = false): number {
        let ret: number = 0;

        for (let i = 0; i < 8; ++i) {
            ret |= this.crypto1Bit(state, Crypto1.BIT(input, i), isEncrypted) << i;
        }

        return ret;
    }

    static crypto1Word(state: Crypto1State, input: number = 0, isEncrypted: boolean = false): number {
        let ret: number = 0;

        for (let i = 0; i < 32; ++i) {
            ret |= this.crypto1Bit(state, Crypto1.BEBIT(input, i), isEncrypted) << (i ^ 24);
        }

        return ret;
    }

    static encrypt(state: Crypto1State, data: number[], parity: number[], offset: number, length: number, isIn: boolean = false): void {
        const end: number = offset + length;
        for (let i = offset; i < end; i++) {
            // compute Parity
            parity[i] = this.oddParity8(data[i]);
            // encrypt data
            data[i] ^= this.crypto1Byte(state, isIn ? data[i] : 0);
            // encrypt Parity
            parity[i] ^= state.peekCrypto1Bit;
        }
    }

    static BIT(x: number, n: number): number {
        return ((x) >> (n) & 1)
    }
    static BEBIT(x: number, n: number): number {
        return Crypto1.BIT(x, (n) ^ 24)
    }

    static filter(x: number): number {
        let f: number;
        f = (0xf22c0 >> (x & 0xf)) & 16;
        f |= (0x6c9c0 >> ((x >> 4) & 0xf)) & 8;
        f |= (0x3c8b0 >> ((x >> 8) & 0xf)) & 4;
        f |= (0x1e458 >> ((x >> 12) & 0xf)) & 2;
        f |= (0x0d938 >> ((x >> 16) & 0xf)) & 1;
        return Crypto1.BIT(0xEC57E80A, f);
    }

    static readonly OddByteParity: number[] = [
        1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
        0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
        0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
        1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
        0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
        1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
        1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
        0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
        0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
        1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
        1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
        0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
        1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
        0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
        0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
        1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1
    ];

    static oddParity8(x: number): number {
        return this.OddByteParity[x];
    }

    static evenParity8(x: number): number {
        return this.oddParity8(x) ^ 1;
    }

    static evenParity32(x: number): number {
        x ^= x >> 16;
        x ^= x >> 8;
        return this.evenParity8(x & 0xFF);
    }

    // helper used to obscure the keystream during authentication
    static prngSuccessor(x: number, n: number): number {
        x = this.swapEndian(x);
        while (n-- > 0) {
            //x = (x >> 1) | ((x >> 16) ^ (x >> 18) ^ (x >> 19) ^ (x >> 21)) << 31;
            x = x >>> 1 | (x >>> 16 ^ x >>> 18 ^ x >>> 19 ^ x >>> 21) << 31;
        }
        return this.swapEndian(x);
    }

    static swapEndian(x: number): number {
        x = (x >>> 8 & 0xff00ff) | (x & 0xff00ff) << 8;
	    x = x >>> 16 | x << 16;
	    return x;
        //return ((x >>> 24) & 0xff) | ((x >>> 8) & 0xff00) | ((x & 0xff00) << 8) | ((x & 0xff) << 24);
    }
}