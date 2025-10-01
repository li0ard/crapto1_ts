/**
 * mfkey64 for TypeScript
 * 
 * Ported from https://github.com/RfidResearchGroup/proxmark3/blob/master/tools/mfc/card_only/nonce2key.c by li0ard
 */

import { lfsr_common_prefix } from "../src";

if (process.argv.length < 6) {
    console.log('Usage: [bun/node] ' + process.argv[1] + ' <uid> <nt> <par> <ks>');
    console.log('Example: [bun/node] nonce2key.ts 92c0456b 73294ab7 a3fbfb537343eb7b 070608090e060a02');
    process.exit(1);
}

const dec2hex = (dec: number, bits: number): string => (dec < 0) ? (Math.pow(2, bits) + dec).toString(16).padStart(bits / 4, '0') : dec.toString(16).padStart(bits / 4, '0');

const uid = parseInt(process.argv[2], 16);
const nt = parseInt(process.argv[3], 16);
const par_info = BigInt(`0x${process.argv[4]}`);
const ks_info = BigInt(`0x${process.argv[5]}`);


console.log(`MIFARE Classic key recovery - nonce2key
    Recovering key for:
      uid: ${dec2hex(uid, 32)}
       nt: ${dec2hex(nt, 32)}
      par: ${par_info.toString(16).padStart(16, "0")}
       ks: ${ks_info.toString(16).padStart(16, "0")}\n`);

let nr, rr;
const ks3x = Array<number>(8).fill(0), par = Array.from({ length: 8 }, () => Array(8).fill(0));
nr = rr = 0;
nr &= 0xffffff1f;

for (let pos = 0; pos < 8; pos++ ) {
    ks3x[7-pos] = Number((ks_info >> BigInt(pos*8)) & 0x0fn);
    const bt = Number((par_info >> BigInt(pos*8)) & 0xffn);
    for (let i = 0; i < 8; i++) par[7-pos][i] = (bt >> i) & 0x01;
}

console.log(`+----+--------+---+-----+---------------+\n|diff|  {nr}  |ks3|ks3^5|    parity     |\n+----+--------+---+-----+---------------+`);

for (let i = 0; i < 8; i++) {
    const nr_diff = (nr | i << 5) >>> 0;
    process.stdout.write(`| ${dec2hex(i << 5, 8)} |${dec2hex(nr_diff, 32)}| ${dec2hex(ks3x[i], 4)} |  ${dec2hex(ks3x[i] ^ 5, 4)}  |`);
    for (let pos = 0; pos < 7; pos++) process.stdout.write(`${dec2hex(par[i][pos], 4)},`);
    console.log(`${dec2hex(par[i][7], 4)}|`)
}
console.log(`+----+--------+---+-----+---------------+`);

const state = lfsr_common_prefix(0, 0, ks3x, par, false)[0];
state.rollback_word(uid^nt);
console.log(`\nFound Key: [${state.lfsr.toString(16).padStart(12, "0")}]`);