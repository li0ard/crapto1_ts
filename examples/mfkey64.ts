/**
 * mfkey64 for TypeScript
 * 
 * Ported from https://github.com/equipter/mfkey by li0ard
 */
import { lfsr_recovery64, prng_successor } from "../src";

if (process.argv.length < 7) {
    console.log('Usage: [bun/node] ' + process.argv[1] + ' <uid> <tag challenge> <reader challenge> <reader response> <tag response>');
    console.log('Example: [bun/node] mfkey64.ts 14579f69 ce844261 f8049ccb 0525c84f 9431cc40');
    process.exit(1);
}

const dec2hex = (dec: number, bits: number): string => (dec < 0) ? (Math.pow(2, bits) + dec).toString(16).padStart(bits / 4, '0') : dec.toString(16).padStart(bits / 4, '0');

const uid = parseInt(process.argv[2], 16);
const chal = parseInt(process.argv[3], 16);
const rchal = parseInt(process.argv[4], 16);
const rresp = parseInt(process.argv[5], 16);
const tresp = parseInt(process.argv[6], 16);

const encc = process.argv.length - 7;
const enclen: number[] = Array(encc);
const enc: number[][] = Array.from({ length: encc }, () => new Array(120));

for (let i = 0; i < encc; i++) {
    enclen[i] = (process.argv[i + 7].length) / 2;
    for (let i2 = 0; i2 < enclen[i]; i2++) enc[i][i2] = parseInt(process.argv[i + 7].substring(i2 * 2, i2 * 2 + 2), 16);
}

console.log(`MIFARE Classic key recovery - based 64 bits of keystream
Recovering key for:
  uid: ${dec2hex(uid, 32)}
   nt: ${dec2hex(chal, 32)}
 {nr}: ${dec2hex(rchal, 32)}
 {ar}: ${dec2hex(rresp, 32)}
 {at}: ${dec2hex(tresp, 32)}\n`);

for (let i = 0; i < encc; i++) {
    process.stdout.write(`{enc${i}}: `);
    for (let i2 = 0; i2 < enclen[i]; i2++) process.stdout.write(dec2hex(enc[i][i2], 8));
    console.log("");
}

const p64 = prng_successor(chal, 64);
console.log(`\nLFSR successors of the tag challenge:
  nt': ${dec2hex(p64, 32)}
 nt'': ${dec2hex(prng_successor(p64, 32), 32)}\n`);

const ks2 = rresp ^ p64;
const ks3 = tresp ^ prng_successor(p64, 32);

console.log(`Keystream used to generate {ar} and {at}:
  ks2: ${dec2hex(ks2, 32)}
  ks3: ${dec2hex(ks3, 32)}\n`);

const s = lfsr_recovery64(ks2, ks3)[0];

if(process.argv.length > 7) {
    console.log("Decrypted communication:");
    let ks4 = 0;
    let rollb = 0;
    for (let i = 0; i < encc; i++) {
        process.stdout.write(`{dec${i}}: `);
        for (let i2 = 0; i2 < enclen[i]; i2++) {
            ks4 = s.byte(0);
            process.stdout.write(dec2hex(ks4 ^ enc[i][i2], 8));
            rollb += 1;
        }
        console.log("");
    }
    for (let i = 0; i < rollb; i++) s.rollback_byte(0);
}
const postAuthState = s.lfsr;
s.rollback_word();
s.rollback_word();
s.rollback_word(rchal, true);
s.rollback_word(uid^chal);

console.log(`\nFound Key: [${s.lfsr.toString(16).padStart(12, "0")}]\nPost-auth state: [${postAuthState.toString(16).padStart(12, "0")}]`);