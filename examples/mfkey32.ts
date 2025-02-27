/**
 * mfkey32 for TypeScript
 * 
 * Ported from https://github.com/equipter/mfkey by li0ard
 */

import { crypto1_word, lfsr_recovery32, lfsr_rollback_word, prng_successor } from "../src";

if (process.argv.length < 9) {
    console.log('Usage: [bun/node] ' + process.argv[1] + ' <uid> <tag challenge> <reader challenge> <reader response> <tag challenge #2> <reader challenge #2> <reader response #2>')
    console.log('Example: [bun/node] mfkey32.ts 23a12659 182c6685 3893952a 9613a859 b3aac455 f05e18ac 2c479869')
    process.exit(1)
}

const dec2hex = (dec: number, bits: number) => {
    if (dec < 0) {
        return (Math.pow(2, bits) + dec).toString(16).padStart(bits / 4, '0')
    } else {
        return dec.toString(16).padStart(bits / 4, '0');
    }
}

const uid = parseInt(process.argv[2], 16)
const chal = parseInt(process.argv[3], 16)
const rchal = parseInt(process.argv[4], 16)
const rresp = parseInt(process.argv[5], 16)
const chal2 = parseInt(process.argv[6], 16)
const rchal2 = parseInt(process.argv[7], 16)
const rresp2 = parseInt(process.argv[8], 16)

console.log(`MIFARE Classic key recovery - based 32 bits of keystream
Recover key from two 32-bit reader authentication answers only

Recovering key for:
    uid: ${dec2hex(uid, 32)}
   nt_0: ${dec2hex(chal, 32)}
 {nr_0}: ${dec2hex(rchal, 32)}
 {ar_0}: ${dec2hex(rresp, 32)}
   nt_1: ${dec2hex(chal2, 32)}
 {nr_1}: ${dec2hex(rchal2, 32)}
 {ar_1}: ${dec2hex(rresp2, 32)}\n`)

const p64 = prng_successor(chal, 64)
const p64b = prng_successor(chal2, 64);

console.log(`LFSR successors of the tag challenge:
  nt': ${dec2hex(p64, 32)}
 nt'': ${dec2hex(p64b, 32)}\n`)

let ks2 = rresp ^ p64;

console.log(`Keystream used to generate {ar} and {at}:
  ks2: ${dec2hex(ks2, 32)}\n`)

let s = lfsr_recovery32(rresp ^ p64, 0);
for (let t = 0; (s[t].odd !== 0) || (s[t].even !== 0); ++t) {
    lfsr_rollback_word(s[t], 0, false);
    lfsr_rollback_word(s[t], rchal, true);
    lfsr_rollback_word(s[t], uid ^ chal, false);
    let key = s[t].lfsr
    crypto1_word(s[t], uid ^ chal2, false);
    crypto1_word(s[t], rchal2, true);
    if (rresp2 === (crypto1_word(s[t], 0, false) ^ prng_successor(chal2, 64))) {
        console.log(`Found Key: [${key.toString(16).padStart(12, "0")}]`)
        break;
    }
}