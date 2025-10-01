export const LF_POLY_ODD: number = 0x29CE5C;
export const LF_POLY_EVEN: number = 0x870804;

export const S1: Readonly<number[]> = [0x62141, 0x310A0, 0x18850, 0x0C428, 0x06214, 0x0310A, 0x85E30, 0xC69AD, 0x634D6, 0xB5CDE, 0xDE8DA, 0x6F46D, 0xB3C83, 0x59E41, 0xA8995, 0xD027F, 0x6813F, 0x3409F, 0x9E6FA];
export const S2: Readonly<number[]> = [0x3A557B00, 0x5D2ABD80, 0x2E955EC0, 0x174AAF60, 0x0BA557B0, 0x05D2ABD8, 0x0449DE68, 0x048464B0, 0x42423258, 0x278192A8, 0x156042D0, 0x0AB02168, 0x43F89B30, 0x61FC4D98, 0x765EAD48, 0x7D8FDD20, 0x7EC7EE90, 0x7F63F748, 0x79117020];
export const T1: Readonly<number[]> = [0x4F37D, 0x279BE, 0x97A6A, 0x4BD35, 0x25E9A, 0x12F4D, 0x097A6, 0x80D66, 0xC4006, 0x62003, 0xB56B4, 0x5AB5A, 0xA9318, 0xD0F39, 0x6879C, 0xB057B, 0x582BD, 0x2C15E, 0x160AF, 0x8F6E2, 0xC3DC4, 0xE5857, 0x72C2B, 0x39615, 0x98DBF, 0xC806A, 0xE0680, 0x70340, 0x381A0, 0x98665, 0x4C332, 0xA272C];
export const T2: Readonly<number[]> = [0x3C88B810, 0x5E445C08, 0x2982A580, 0x14C152C0, 0x4A60A960, 0x253054B0, 0x52982A58, 0x2FEC9EA8, 0x1156C4D0, 0x08AB6268, 0x42F53AB0, 0x217A9D58, 0x161DC528, 0x0DAE6910, 0x46D73488, 0x25CB11C0, 0x52E588E0, 0x6972C470, 0x34B96238, 0x5CFC3A98, 0x28DE96C8, 0x12CFC0E0, 0x4967E070, 0x64B3F038, 0x74F97398, 0x7CDC3248, 0x38CE92A0, 0x1C674950, 0x0E33A4A8, 0x01B959D0, 0x40DCACE8, 0x26CEDDF0];
export const C1: Readonly<number[]> = [0x846B5, 0x4235A, 0x211AD];
export const C2: Readonly<number[]> = [0x1A822E0, 0x21A822E0, 0x21A822E0];
export const fastfwd: Readonly<number[]> = [0, 0x4BC53, 0xECB1, 0x450E2, 0x25E29, 0x6E27A, 0x2B298, 0x60ECB, 0, 0x1D962, 0x4BC53, 0x56531, 0xECB1, 0x135D3, 0x450E2, 0x58980];

/** Helper used to obscure the keystream during authentication */
export const prng_successor = (x: number, n: number): number => {
    x = swapendian(x);
    while ((n--) > 0) x = x >>> 1 | (x >>> 16 ^ x >>> 18 ^ x >>> 19 ^ x >>> 21) << 31;
    return swapendian(x);
}

/** Get bit of `num` at position `index` */
export const bit = (num: number, index: number): number => ((num >>> index) & 1);

/** Get bit of reversed endian 32-bit `num` at position `index` */
export const bebit = (num: number, index: number): number => bit(num, index ^ 24);

export const bitBigInt = (x: bigint, n: number): bigint => ((x >> BigInt(n)) & 1n);

/** Filter function of Crypto1. Compute one bit of keystream from LFSR bits */
export const filter = (x: number): number => {
    let f: number = 0;
    f |= (0xf22c0 >>> (x & 0xf) & 16) !== 0 ? 16 : 0;
    f |= (0x6c9c0 >>> (x >>> 4 & 0xf) & 8) !== 0 ? 8 : 0;
    f |= (0x3c8b0 >>> (x >>> 8 & 0xf) & 4) !== 0 ? 4 : 0;
    f |= (0x1e458 >>> (x >>> 12 & 0xf) & 2) !== 0 ? 2 : 0;
    f |= (0x0d938 >>> (x >>> 16 & 0xf) & 1) !== 0 ? 1 : 0;
    return bit(0xEC57E80A, f);
}

/** Get parity from number */
export const parity = (x: number): number => {
    x ^= x >>> 16;
    x ^= x >>> 8;
    x ^= x >>> 4;
    return bit(0x6996, x & 0xf);
}

/** Binary search for the first occurence of stop's MSB in sorted */
export const binsearch = (data: number[], start: number, stop: number): number => {
    let mid: number, val: number = data[stop] & 0xff000000;
    while (start !== stop) {
        mid = (stop - start) >> 1;
        if ((data[start + mid] ^ 0x80000000) > (val ^ 0x80000000)) stop = start + mid;
        else start += mid + 1;
    }
    return start;
}

export const quicksort = (data: number[], start: number, stop: number): void => {
    let it: number = start + 1, rit: number = stop, t: number;
    if (it > rit) return;
    while (it < rit) {
        if ((data[it] ^ 0x80000000) <= (data[start] ^ 0x80000000)) ++it;
        else if ((data[rit] ^ 0x80000000) > (data[start] ^ 0x80000000)) --rit;
        else {
            t = data[it];
            data[it] = data[rit];
            data[rit] = t;
        }
    }
    if ((data[rit] ^ 0x80000000) >= (data[start] ^ 0x80000000)) --rit;
    if (rit !== start) {
        t = data[rit];
        data[rit] = data[start];
        data[start] = t;
    }
    quicksort(data, start, rit - 1);
    quicksort(data, rit + 1, stop);
}

/** Helper, calculates the partial linear feedback contributions and puts in MSB */
export const update_contribution = (data: number[], item: number, mask1: number, mask2: number): number[] => {
    let p: number = data[item] >>> 25;
    p = p << 1 | parity(data[item] & mask1);
    p = p << 1 | parity(data[item] & mask2);
    data[item] = p << 24 | (data[item] & 0xffffff);

    return data
}

/**
 * Using a bit of the keystream extend the table of possible lfsr states (complex version)
 * @param data Result table
 * @param tbl Array of even/odd bits of lfsr
 * @param size Size of array
 * @param bit Bit of keystream
 * @param m1 mask1
 * @param m2 mask2
 * @param input Value that was fed into lfsr at time keystream was generated
 */
export const extend_table = (data: number[], tbl: number, size: number, bit: number, m1: number, m2: number, input: number): number => {
    input <<= 24;
    for (data[tbl] <<= 1; tbl <= size; data[++tbl] <<= 1) {
        if ((filter(data[tbl]) ^ filter(data[tbl] | 1)) !== 0) {
            data[tbl] |= filter(data[tbl]) ^ bit;
            data = update_contribution(data, tbl, m1, m2);
            data[tbl] ^= input;
        } else if (filter(data[tbl]) === bit) {
            data[++size] = data[tbl + 1];
            data[tbl + 1] = data[tbl] | 1;
            data = update_contribution(data, tbl, m1, m2);
            data[tbl++] ^= input;
            data = update_contribution(data, tbl, m1, m2);
            data[tbl] ^= input;
        }
        else data[tbl--] = data[size--];
    }
    return size;
}

/**
 * Using a bit of the keystream extend the table of possible lfsr states (simple version)
 * @param tbl Array of even/odd bits of lfsr
 * @param size Size of array 
 * @param bit Bit of keystream
 */
export const extend_table_simple = (tbl: number[], size: number, bit: number): number => {
    let i = 0;
    for (tbl[i] <<= 1; i <= size; tbl[++i] <<= 1) {
        if ((filter(tbl[i]) ^ filter(tbl[i] | 1)) !== 0) tbl[i] |= filter(tbl[i]) ^ bit;
        else if (filter(tbl[i]) === bit) {
            tbl[++size] = tbl[++i];
            tbl[i] = tbl[i - 1] | 1;
        }
        else tbl[i--] = tbl[size--];
    }
    return size;
}

export const oddByteParity: number[] = [
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

/** Return odd parity of unsigned 8-bit `x` */
export const oddParity8 = (x: number): number => oddByteParity[x];
/** Return even parity of unsigned 8-bit `x` */
export const evenParity8 = (x: number): number => oddParity8(x) ^ 1;
/** Return even parity of unsigned 32-bit `x` */
export const evenParity32 = (x: number): number => {
    x ^= x >> 16;
    x ^= x >> 8;
    return evenParity8(x & 0xFF);
}

/** Swaps endianness of given number */
export const swapendian = (x: number): number => {
    x = (x >>> 8 & 0xff00ff) | (x & 0xff00ff) << 8;
    x = x >>> 16 | x << 16;
    return x;
}