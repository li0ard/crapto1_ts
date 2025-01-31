import { expect, test, it } from "bun:test"
import { Crypto1State, recovery32 } from "../src/"
import { filter } from "../src/utils"

test("Recovery by 2 auths", () => {
    it("Real card", () => {
        expect(recovery32(
            0x23A12659,
            0x182c6685,
            0x3893952A,
            0x9613a859,
            0xb3aac455,
            0xf05e18ac,
            0x2c479869
        )).toBe(0xe23ecc65d921n)
    })
    
    it("proxmark3 sample", () => {
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
