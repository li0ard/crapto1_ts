/**
 * mfkey32nested by doegox for TypeScript
 * 
 * Ported from https://github.com/RfidResearchGroup/proxmark3/blob/master/tools/mfc/card_reader/mfkey32nested.c by li0ard
 */

import { crypto1_word, lfsr_recovery32, lfsr_rollback_word, prng_successor } from "../src";

if (process.argv.length < 7) {
    console.log('Usage: [bun/node] ' + process.argv[1] + ' <uid> <nt> <{nt}> <{nr}> <{ar}>')
    console.log('Example: [bun/node] mfkey32nested.ts 5c467f63 4bbf8a12 abb30bd1 46033966 adc18162')
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
const enc_chal = parseInt(process.argv[4], 16)
const rchal = parseInt(process.argv[5], 16)
const rresp = parseInt(process.argv[6], 16)

console.log(`MIFARE Classic key recovery - based 32 bits of keystream
Recover key from one reader authentication answer only
    
Recovering key for:
    uid: ${dec2hex(uid, 32)}
     nt: ${dec2hex(chal, 32)}
   {nt}: ${dec2hex(enc_chal, 32)}
   {nr}: ${dec2hex(rchal, 32)}
   {ar}: ${dec2hex(rresp, 32)}\n`)

let ar = prng_successor(chal, 64);
let ks0 = enc_chal ^ chal;
let ks2 = rresp ^ ar;

console.log(`\nLFSR successor of the tag challenge:`)
console.log(`     ar: ${dec2hex(ar, 32)}`)
console.log(`\nKeystream used to generate {nt}:
    ks0: ${dec2hex(ks0, 32)}`)
console.log(`\nKeystream used to generate {ar}:
    ks2: ${dec2hex(ks2, 32)}`)

let s = lfsr_recovery32(ks0, uid ^ chal);

for (let t = 0; (s[t].odd !== 0) || (s[t].even !== 0); t++) {
    crypto1_word(s[t], rchal, true);
    if(ks2 == crypto1_word(s[t], 0)) {
        lfsr_rollback_word(s[t], 0);
        lfsr_rollback_word(s[t], rchal, true);
        lfsr_rollback_word(s[t], uid ^ chal);
        let key = s[t].lfsr
        console.log(`\nFound Key: [${key.toString(16).padStart(12, "0")}]`)
        break;
    }
}