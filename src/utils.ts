/**
 * Get bit of `num` at position `index`
 * @param num Number
 * @param index Index
 * @returns {number}
 */
export const bit = (num: number, index: number): number => {
    return ((num >>> index) & 1);
}

/**
 * Get bit of reversed endian 32-bit `num` at position `index`
 * @param num Word
 * @param index Index
 * @returns {number}
 */
export const bebit = (num: number, index: number): number => {
    return bit(num, index ^ 24);
}

/**
 * Filter function of Crypto1.
 * 
 * Compute one bit of keystream from LFSR bits
 * @param x LFSR bits
 * @returns {number}
 */
export const filter = (x: number): number => {
    let f: number = 0;
    f |= (0xf22c0 >>> (x & 0xf) & 16) !== 0 ? 16 : 0;
    f |= (0x6c9c0 >>> (x >>> 4 & 0xf) & 8) !== 0 ? 8 : 0;
    f |= (0x3c8b0 >>> (x >>> 8 & 0xf) & 4) !== 0 ? 4 : 0;
    f |= (0x1e458 >>> (x >>> 12 & 0xf) & 2) !== 0 ? 2 : 0;
    f |= (0x0d938 >>> (x >>> 16 & 0xf) & 1) !== 0 ? 1 : 0;
    return bit(0xEC57E80A, f);
}

/**
 * Get parity from number
 * @param x Number 
 * @returns {number}
 */
export const parity = (x: number): number => {
    x ^= x >>> 16;
    x ^= x >>> 8;
    x ^= x >>> 4;
    return bit(0x6996, x & 0xf);
}

/**
 * Binary search for the first occurence of stop's MSB in sorted
 */
export const binsearch = (data: number[], start: number, stop: number): number => {
    let mid: number, val: number = data[stop] & 0xff000000;
    while (start !== stop) {
        mid = (stop - start) >> 1;
        if ((data[start + mid] ^ 0x80000000) > (val ^ 0x80000000)) {
            stop = start + mid;
        } else {
            start += mid + 1;
        }
    }
    return start;
}

export const quicksort = (data: number[], start: number, stop: number): void => {
    let it: number = start + 1, rit: number = stop, t: number;
    if (it > rit) return;
    while (it < rit) {
        if ((data[it] ^ 0x80000000) <= (data[start] ^ 0x80000000)) {
            ++it;
        } else if ((data[rit] ^ 0x80000000) > (data[start] ^ 0x80000000)) {
            --rit;
        } else {
            t = data[it];
            data[it] = data[rit];
            data[rit] = t;
        }
    }
    if ((data[rit] ^ 0x80000000) >= (data[start] ^ 0x80000000)) {
        --rit;
    }
    if (rit !== start) {
        t = data[rit];
        data[rit] = data[start];
        data[start] = t;
    }
    quicksort(data, start, rit - 1);
    quicksort(data, rit + 1, stop);
}

/**
 * Helper, calculates the partial linear feedback contributions and puts in MSB
 * @param data Input number
 * @param item Input index
 * @param mask1
 * @param mask2
 * @returns {void}
 */
export const update_contribution = (data: number[], item: number, mask1: number, mask2: number): void => {
    let p: number = data[item] >>> 25;
    p = p << 1 | parity(data[item] & mask1);
    p = p << 1 | parity(data[item] & mask2);
    data[item] = p << 24 | (data[item] & 0xffffff);
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
 * @returns {number}
 */
export const extend_table = (data: number[], tbl: number, size: number, bit: number, m1: number, m2: number, input: number): number => {
    input <<= 24;
    for (data[tbl] <<= 1; tbl <= size; data[++tbl] <<= 1) {
        if ((filter(data[tbl]) ^ filter(data[tbl] | 1)) !== 0) {
            data[tbl] |= filter(data[tbl]) ^ bit;
            update_contribution(data, tbl, m1, m2);
            data[tbl] ^= input;
        } else if (filter(data[tbl]) === bit) {
            data[++size] = data[tbl + 1];
            data[tbl + 1] = data[tbl] | 1;
            update_contribution(data, tbl, m1, m2);
            data[tbl++] ^= input;
            update_contribution(data, tbl, m1, m2);
            data[tbl] ^= input;
        } else {
            data[tbl--] = data[size--];
        }
    }
    return size;
}

/**
 * Using a bit of the keystream extend the table of possible lfsr states (simple version)
 * @param tbl Array of even/odd bits of lfsr
 * @param size Size of array 
 * @param bit Bit of keystream
 * @returns {number}
 */
export const extend_table_simple = (tbl: number[], size: number, bit: number): number => {
    let i = 0;
    for (tbl[i] <<= 1; i <= size; tbl[++i] <<= 1) {
        if ((filter(tbl[i]) ^ filter(tbl[i] | 1)) !== 0) {
            tbl[i] |= filter(tbl[i]) ^ bit;
        } else if (filter(tbl[i]) === bit) {
            tbl[++size] = tbl[++i];
            tbl[i] = tbl[i - 1] | 1;
        } else {
            tbl[i--] = tbl[size--];
        }
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
]

/**
 * Return odd parity of unsigned 8-bit `x`
 * @param x Number
 * @returns {number}
 */
export const oddParity8 = (x: number): number => {
    return oddByteParity[x];
}

/**
 * Return even parity of unsigned 8-bit `x`
 * @param x Number
 * @returns {number}
 */
export const evenParity8 = (x: number): number => {
    return oddParity8(x) ^ 1;
}

/**
 * Return even parity of unsigned 32-bit `x`
 * @param x Number
 * @returns {number}
 */
export const evenParity32 = (x: number): number => {
    x ^= x >> 16;
    x ^= x >> 8;
    return evenParity8(x & 0xFF);
}

/**
 * Swaps endianness of given number
 * @param x Number to swap
 * @returns {number}
 */
export const swapendian = (x: number): number => {
    x = (x >>> 8 & 0xff00ff) | (x & 0xff00ff) << 8;
    x = x >>> 16 | x << 16;
    return x;
}