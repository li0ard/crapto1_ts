import { bit, filter } from "./utils";

/** Crypto1 state */
export class Crypto1State {
    odd: number;
    even: number;

    constructor(odd: number = 0, even: number = 0) {
        this.odd = odd;
        this.even = even;
    }
    
    /**
     * Initialize state from key (aka LFSR value)
     * @param key 
     * @returns 
     */
    static fromKey(key: bigint): Crypto1State {
        let odd = 0n
        let even = 0n
        const bitBigInt = (x: bigint, n: number) => ((x >> BigInt(n)) & 1n);

        for (let i = 47; i > 0; i -= 2) {
            odd = odd << 1n | bitBigInt(key, (i - 1) ^ 7);
            even = even << 1n | bitBigInt(key, i ^ 7);
        }
        return new Crypto1State(Number(odd), Number(even))
    }

    /** Get LFSR value (aka Key) */
    get lfsr(): bigint {
        let lfsr = 0n
        for (let i = 23; i >= 0; --i) {
            lfsr = lfsr << 1n | BigInt(bit(this.odd, i ^ 3));
            lfsr = lfsr << 1n | BigInt(bit(this.even, i ^ 3));
        }
        return lfsr;
    }

    /** Get next Crypto1 bit */
    get peekCrypto1Bit(): number {
        return filter(this.odd);
    }
}