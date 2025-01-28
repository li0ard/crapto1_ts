import { Crypto1 } from "./legacy/crypto1";

export class Crypto1State {
    public odd: number;
    public even: number;

    constructor(odd: number, even: number);
    constructor(key: bigint);
    constructor(arg1: number | bigint, arg2?: number) {
        if (typeof arg1 === "bigint") {
            const key = arg1;
            this.odd = 0;
            this.even = 0;
            for (let i = 47; i > 0; i -= 2) {
                this.odd = (this.odd << 1) | this.bit(key, (i - 1) ^ 7);
                this.even = (this.even << 1) | this.bit(key, i ^ 7);
            }
        } else {
            this.odd = arg1;
            this.even = arg2!;
        }
    }

    private bit(key: bigint, position: number): number {
        // Assuming the method to get specific bit from key
        return (key >> BigInt(position)) & BigInt(1) ? 1 : 0;
    }

    public get lfsr(): bigint {
        let lfsr = BigInt(0);
        for (let i = 23; i >= 0; --i) {
            lfsr = (lfsr << BigInt(1)) | BigInt(this.bit(BigInt(this.odd), i ^ 3));
            lfsr = (lfsr << BigInt(1)) | BigInt(this.bit(BigInt(this.even), i ^ 3));
        }
        return lfsr;
    }

    public get peekCrypto1Bit(): number {
        return Crypto1.filter(this.odd);
    }
}