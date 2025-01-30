import { expect, test, it } from "bun:test"
import { recovery32 } from "../src/"

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