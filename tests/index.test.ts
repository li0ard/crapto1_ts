import { expect, test } from "bun:test"
import { Crypto1State, encrypt, lfsr_rollback_byte, recovery32, recovery64 } from "../src/"
import { filter } from "../src/utils"

test("Recovery by 2 auths", () => {
    // Real card
    expect(recovery32(
        0x23A12659,
        0x182c6685,
        0x3893952A,
        0x9613a859,
        0xb3aac455,
        0xf05e18ac,
        0x2c479869
    )).toBe(0xe23ecc65d921n)
    
    // proxmark3 sample
    expect(recovery32(
        0x939be0d5,
        0x4e70d691,
        0xb3a576be,
        0x02c1559b,
        0xc6efb126,
        0xd24dd966,
        0x03fc7386
    )).toBe(0xa0a1a2a3a4a5n)
})

test("Recovery by 1 auth", () => {
    // proxmark3 sample
    expect(recovery64(
        0x14579f69,
        0xce844261,
        0xf8049ccb,
        0x0525c84f,
        0x9431cc40
    )).toBe(0x091e639cb715n)

    // crapto1gui sample
    expect(recovery64(
        0xc108416a,
        0xabcd1949,
        0x59d5920f,
        0x15b9d553,
        0xa79a3fee
    )).toBe(0x62bea192fa37n)
})

test("State", () => {
    let testData = [
        [0xd73A52b491AAn, 0x009E831F, 0x00F236A0],
        [0x9D29AE25242An, 0x0056f22E, 0x00E84C40],
        [0x1FA3E73CAC0An, 0x00CBB67C, 0x00E8D640],
        [0xD1C9DB532E82n, 0x0015D8E9, 0x00B9BB40],
        [0x239186C46E88n, 0x00A191E5, 0x008A4550],
        [0x091e639cb715n, 5023152, 8820462]
    ]

    for(let i of testData) {
        const s = Crypto1State.fromKey(i[0] as bigint)
        expect(s.odd).toBe(i[1] as number)
        expect(s.even).toBe(i[2] as number)
        expect(s.lfsr).toBe(i[0] as bigint)
        expect(s.peekCrypto1Bit).toBe(filter(s.odd))
    }
})

test("Encryption", () => {
    let s = Crypto1State.fromKey(0x708076d3560en)
    // Encrypt
    expect(encrypt(s, [112, 147, 223, 153])).toEqual([48, 20, 167, 254])

    // Rollback state
    for(let i = 0; i < 4; i++) lfsr_rollback_byte(s, 0);
    expect(s.lfsr).toBe(0x708076d3560en)

    // Decrypt
    expect(encrypt(s, [48, 20, 167, 254])).toEqual([112, 147, 223, 153])
})