import { crypto1_word, Crypto1State, oddParity8, prng_successor } from "../src"

const UID  = 0x0DB3FA11
const NT   = 0xE0512BB5
const NR   = 0x12345678
const KEY1 = 0xFFFFFFFFFFFFn
const NESTED_NT  = 0xBF53BA5F
const NESTED_NR  = 0x12345678
const NESTED_KEY = 0xFFFFFFFFFFFFn

const dec2hex = (dec: number, bits: number) => {
    if (dec < 0) {
        return (Math.pow(2, bits) + dec).toString(16).padStart(bits / 4, '0')
    } else {
        return dec.toString(16).padStart(bits / 4, '0');
    }
}

const append_crc16_a = (buf: number[],) => {
    let crc = 0x6363;
    for (let i = 0; i < 2; i++) {
        crc ^= buf[i];
        for (let j = 0; j < 8; j++) {
            if (crc & 0x0001) {
                crc = (crc >> 1) ^ 0x8408;
            } else {
                crc >>= 1;
            }
        }
    }

    return [crc & 0xFF, (crc >> 8) & 0xFF]
}

console.log("Crypto-1 protocol demo\n\nFirst Authentication Protocol")
console.log("Reader                          <>  Tag\n======                          <>  ===")

let tag_uid = UID
console.log(`                                <-  uid (via anticol)                   < ${dec2hex(tag_uid, 32)}`)

let reader_uid = tag_uid

console.log(`s = crypto1_create(key)                                                   ${KEY1.toString(16)}`)
let reader_ui64Key = KEY1
let reader_state = Crypto1State.fromKey(reader_ui64Key)

let cmd = [0x60, 0x00]
cmd = cmd.concat(append_crc16_a(cmd))
console.log(`auth A/B+blk + CRC              ->                                      > ${cmd.map(x => dec2hex(x, 8)).join('')}`)

console.log(`                                    s = crypto1_create(key)               ${KEY1.toString(16)}`)
let tag_ui64Key = KEY1;
let tag_state = Crypto1State.fromKey(tag_ui64Key)

let tag_nt = NT;
console.log(`                                    Gen nT                                ${dec2hex(tag_nt, 32)}`)

process.stdout.write("                                    ks0 = crypto1_word(s, uid ^ nT, 0)    ")
let tag_ks0 = crypto1_word(tag_state, tag_uid ^ tag_nt);
console.log(dec2hex(tag_ks0, 32))

console.log(`                                <-  nT                                  < ${dec2hex(tag_nt, 32)}`)

let reader_nt = tag_nt;

process.stdout.write("ks0 = crypto1_word(s, uid ^ nT, 0)                                        ")
let reader_ks0 = crypto1_word(reader_state, reader_uid ^ reader_nt);
console.log(dec2hex(reader_ks0, 32))

process.stdout.write("Gen nR                                                                    ")
let reader_nr = NR;
console.log(dec2hex(reader_nr, 32))

process.stdout.write("ks1 = crypto1_word(s, nR, 0)                                              ")
let reader_ks1 = crypto1_word(reader_state, reader_nr);
console.log(dec2hex(reader_ks1, 32))

process.stdout.write("{nR} = nR ^ ks1                                                           ")
let reader_nr_enc = reader_nr ^ reader_ks1;
console.log(dec2hex(reader_nr_enc, 32))

process.stdout.write("aR = suc64(nT)                                                            ")
let reader_ar = prng_successor(reader_nt, 64);
console.log(dec2hex(reader_ar, 32))

process.stdout.write("ks2 = crypto1_word(s, 0, 0)                                               ")
let reader_ks2 = crypto1_word(reader_state, 0);
console.log(dec2hex(reader_ks2, 32))

process.stdout.write("{aR} = ks2 ^ aR                                                           ")
let reader_ar_enc = reader_ks2 ^ reader_ar;
console.log(dec2hex(reader_ar_enc, 32))

let reader_ks_next_bit = reader_state.peekCrypto1Bit

process.stdout.write("{nR}|{aR}                       ->                                      > ")
process.stdout.write(dec2hex((reader_nr_enc >> 24) & 0xFF, 8))
process.stdout.write(oddParity8((reader_nr >> 24) & 0xFF) ==
(oddParity8((reader_nr_enc >> 24) & 0xFF) ^ ((reader_ks1 >> 16) & 1)) ? " " : "!")
process.stdout.write(dec2hex((reader_nr_enc >> 16) & 0xFF, 8))
process.stdout.write(oddParity8((reader_nr >> 16) & 0xFF) ==
(oddParity8((reader_nr_enc >> 16) & 0xFF) ^ ((reader_ks1 >> 8) & 1)) ? " " : "!")
process.stdout.write(dec2hex((reader_nr_enc >> 8) & 0xFF, 8))
process.stdout.write(oddParity8((reader_nr >> 8) & 0xFF) ==
(oddParity8((reader_nr_enc >> 8) & 0xFF) ^ ((reader_ks1 >> 0) & 1)) ? " " : "!")
process.stdout.write(dec2hex((reader_nr_enc >> 0) & 0xFF, 8))
process.stdout.write(oddParity8((reader_nr >> 0) & 0xFF) ==
(oddParity8((reader_nr_enc >> 0) & 0xFF) ^ ((reader_ks2 >> 24) & 1)) ? " " : "!")

process.stdout.write(dec2hex((reader_ar_enc >> 24) & 0xFF, 8))
process.stdout.write(oddParity8((reader_ar >> 24) & 0xFF) ==
(oddParity8((reader_ar_enc >> 24) & 0xFF) ^ ((reader_ks2 >> 16) & 1)) ? " " : "!")
process.stdout.write(dec2hex((reader_ar_enc >> 16) & 0xFF, 8))
process.stdout.write(oddParity8((reader_ar >> 16) & 0xFF) ==
(oddParity8((reader_ar_enc >> 16) & 0xFF) ^ ((reader_ks2 >> 8) & 1)) ? " " : "!")
process.stdout.write(dec2hex((reader_ar_enc >> 8) & 0xFF, 8))
process.stdout.write(oddParity8((reader_ar >> 8) & 0xFF) ==
(oddParity8((reader_ar_enc >> 8) & 0xFF) ^ ((reader_ks2 >> 0) & 1)) ? " " : "!")
process.stdout.write(dec2hex((reader_nr_enc >> 0) & 0xFF, 8))
process.stdout.write(oddParity8((reader_ar >> 0) & 0xFF) ==
(oddParity8((reader_ar_enc >> 0) & 0xFF) ^ reader_ks_next_bit) ? " " : "!")

console.log()

let tag_nr_enc = reader_nr_enc;

let tag_ar_enc = reader_ar_enc;
process.stdout.write("                                    ks1 = crypto1_word(s, {nR}, 1)        ")
let tag_ks1 = crypto1_word(tag_state, tag_nr_enc, true);
console.log(dec2hex(tag_ks1, 32))

process.stdout.write("                                    nR = ks1 ^ {nR}                       ")
let tag_nr = tag_ks1 ^ tag_nr_enc
console.log(dec2hex(tag_nr, 32))

process.stdout.write("                                    ks2 = crypto1_word(s, 0, 0)           ")
let tag_ks2 = crypto1_word(tag_state, 0);
console.log(dec2hex(tag_ks2, 32))

process.stdout.write("                                    aR = ks2 ^ {aR}                       ")
let tag_ar = tag_ks2 ^ tag_ar_enc;
console.log(dec2hex(tag_ar, 32))

process.stdout.write("                                    aR == suc64(nT) ?                     ")
process.stdout.write(dec2hex(prng_successor(tag_nt, 64), 32))
process.stdout.write(tag_ar == prng_successor(tag_nt, 64) ? " OK\n" : " FAIL\n")
process.stdout.write("                                    aT = suc96(nT)                        ")
let tag_at = prng_successor(tag_nt, 96);
console.log(dec2hex(tag_at, 32))

process.stdout.write("                                    ks3 = crypto1_word(s, 0, 0)           ")
let tag_ks3 = crypto1_word(tag_state, 0);
console.log(dec2hex(tag_ks3, 32))

process.stdout.write("                                    {aT} = ks3 ^ aT                       ")
let tag_at_enc = tag_ks3 ^ tag_at;
let tag_ks_next_bit = tag_state.peekCrypto1Bit
console.log(dec2hex(tag_at_enc, 32))

process.stdout.write("                                 <- {aT}                                < ")
process.stdout.write(dec2hex((tag_at_enc >> 24) & 0xFF, 8))
process.stdout.write(oddParity8((tag_at >> 24) & 0xFF) ==
(oddParity8((tag_at_enc >> 24) & 0xFF) ^ ((tag_ks3 >> 16) & 1)) ? " " : "!")
process.stdout.write(dec2hex((tag_at_enc >> 16) & 0xFF, 8))
process.stdout.write(oddParity8((tag_at >> 16) & 0xFF) ==
(oddParity8((tag_at_enc >> 16) & 0xFF) ^ ((tag_ks3 >> 8) & 1)) ? " " : "!")
process.stdout.write(dec2hex((tag_at_enc >> 8) & 0xFF, 8))
process.stdout.write(oddParity8((tag_at >> 8) & 0xFF) ==
(oddParity8((tag_at_enc >> 8) & 0xFF) ^ ((tag_ks3 >> 0) & 1)) ? " " : "!")
process.stdout.write(dec2hex((reader_nr_enc >> 0) & 0xFF, 8))
process.stdout.write(oddParity8((tag_at >> 0) & 0xFF) ==
(oddParity8((tag_at_enc >> 0) & 0xFF) ^ tag_ks_next_bit) ? " " : "!")
console.log()

let reader_at_enc = tag_at_enc;
let reader_ks3 = crypto1_word(reader_state, 0);
console.log(`ks3 = crypto1_word(s, 0, 0)                                               ${dec2hex(reader_ks3, 32)}`)

let reader_at = reader_ks3 ^ reader_at_enc;
console.log(`aT = ks3 ^ {aT}                                                           ${dec2hex(reader_at, 32)}`)
console.log(`aT == suc96(nT) ?                                                         ${dec2hex(prng_successor(reader_nt, 96), 32)} ${reader_at == prng_successor(tag_nt, 96) ? "OK" : "FAIL"}`)

console.log("\nNested authentication")
console.log("Reader                          <>  Tag\n======                          <>  ===")
let reader_ks4 = crypto1_word(reader_state, 0);
console.log(`ks4 = crypto1_word(s, 0, 0)                                               ${dec2hex(reader_ks4, 32)}`)
let reader_cmd = (cmd[0] << 24) | (cmd[1] << 16) | (cmd[2] << 8) | (cmd[3] << 0);
let reader_cmd_enc = reader_ks4 ^ reader_cmd;
console.log(`{cmd} = ks4 ^ cmd                                                         ${dec2hex(reader_cmd_enc, 32)}`)
reader_ks_next_bit = reader_state.peekCrypto1Bit;

process.stdout.write("{auth A/B+blk}                  ->                                      > ")
process.stdout.write(dec2hex((reader_cmd_enc >> 24) & 0xFF, 8))
process.stdout.write(oddParity8((reader_cmd >> 24) & 0xFF) ==
(oddParity8((reader_cmd_enc >> 24) & 0xFF) ^ ((reader_ks4 >> 16) & 1)) ? " " : "!")
process.stdout.write(dec2hex((reader_cmd_enc >> 16) & 0xFF, 8))
process.stdout.write(oddParity8((reader_cmd >> 16) & 0xFF) ==
(oddParity8((reader_cmd_enc >> 16) & 0xFF) ^ ((reader_ks4 >> 8) & 1)) ? " " : "!")
process.stdout.write(dec2hex((reader_cmd_enc >> 8) & 0xFF, 8))
process.stdout.write(oddParity8((reader_cmd >> 8) & 0xFF) ==
(oddParity8((reader_cmd_enc >> 8) & 0xFF) ^ ((reader_ks4 >> 0) & 1)) ? " " : "!")
process.stdout.write(dec2hex((reader_cmd_enc >> 0) & 0xFF, 8))
process.stdout.write(oddParity8((reader_cmd >> 0) & 0xFF) ==
(oddParity8((reader_cmd_enc >> 0) & 0xFF) ^ reader_ks_next_bit) ? " " : "!")
console.log()

console.log(`                                    s = crypto1_create(key)`)
let tag2_ui64Key = NESTED_KEY
let tag2_state = Crypto1State.fromKey(tag2_ui64Key)
let tag2_nt = NESTED_NT;

console.log(`                                    Gen nT                                ${dec2hex(tag2_nt, 32)}`)
let tag2_ks0 = crypto1_word(tag2_state, tag_uid ^ tag2_nt);
console.log(`                                    ks0 = crypto1_word(s, uid ^ nT, 0)    ${dec2hex(tag2_ks0, 32)}`)

let tag2_nt_enc = tag2_ks0 ^ tag2_nt;
console.log(`                                    {nT} = ks0 ^ nT                       ${dec2hex(tag2_nt_enc, 32)}`)
let tag2_ks_next_bit = tag2_state.peekCrypto1Bit
process.stdout.write(`                                <-  {nT}                                < `)
process.stdout.write(dec2hex((tag2_nt_enc >> 24) & 0xFF, 8))
process.stdout.write(oddParity8((tag2_nt >> 24) & 0xFF) ==
(oddParity8((tag2_nt_enc >> 24) & 0xFF) ^ ((tag2_ks0 >> 16) & 1)) ? " " : "!")
process.stdout.write(dec2hex((tag2_nt_enc >> 16) & 0xFF, 8))
process.stdout.write(oddParity8((tag2_nt >> 16) & 0xFF) ==
(oddParity8((tag2_nt_enc >> 16) & 0xFF) ^ ((tag2_ks0 >> 8) & 1)) ? " " : "!")
process.stdout.write(dec2hex((tag2_nt_enc >> 8) & 0xFF, 8))
process.stdout.write(oddParity8((tag2_nt >> 8) & 0xFF) ==
(oddParity8((tag2_nt_enc >> 8) & 0xFF) ^ ((tag2_ks0 >> 0) & 1)) ? " " : "!")
process.stdout.write(dec2hex((tag2_nt_enc >> 0) & 0xFF, 8))
process.stdout.write(oddParity8((tag2_nt >> 0) & 0xFF) ==
(oddParity8((tag2_nt_enc >> 0) & 0xFF) ^ tag2_ks_next_bit) ? " " : "!")
console.log()

console.log(`s = crypto1_create(key)`)
let reader2_ui64Key = NESTED_KEY;
let reader2_state = Crypto1State.fromKey(reader2_ui64Key)
let reader2_nt_enc = tag2_nt_enc;

let reader2_ks0 = crypto1_word(reader2_state, reader_uid ^ reader2_nt_enc, true);
console.log(`ks0 = crypto1_word(s, uid ^ {nT}, 1)                                      ${dec2hex(reader2_ks0, 32)}`)

let reader2_nt = reader2_ks0 ^ reader2_nt_enc;
console.log(`nT = ks0 ^ {nT}                                                           ${dec2hex(reader2_nt, 32)}`)

let reader2_nr = NESTED_NR;
console.log(`Gen nR                                                                    ${dec2hex(reader2_nr, 32)}`)

let reader2_ks1 = crypto1_word(reader2_state, reader2_nr);
console.log(`ks1 = crypto1_word(s, nR, 0)                                              ${dec2hex(reader2_ks1, 32)}`)

let reader2_nr_enc = reader2_nr ^ reader2_ks1;
console.log(`{nR} = nR ^ ks1                                                           ${dec2hex(reader2_nr_enc, 32)}`)

let reader2_ar = prng_successor(reader2_nt, 64);
console.log(`aR = suc64(nT)                                                            ${dec2hex(reader2_ar, 32)}`)

let reader2_ks2 = crypto1_word(reader2_state, 0);
console.log(`ks2 = crypto1_word(s, 0, 0)                                               ${dec2hex(reader2_ks2, 32)}`)

let reader2_ar_enc = reader2_ks2 ^ reader2_ar;
console.log(`{aR} = ks2 ^ aR                                                           ${dec2hex(reader2_ar_enc, 32)}`)

let reader2_ks_next_bit = reader2_state.peekCrypto1Bit;
process.stdout.write(`{nR}|{aR}                       ->                                      > `)
process.stdout.write(dec2hex((reader2_nr_enc >> 24) & 0xFF, 8))
process.stdout.write(oddParity8((reader2_nr >> 24) & 0xFF) ==
(oddParity8((reader2_nr_enc >> 24) & 0xFF) ^ ((reader2_ks1 >> 16) & 1)) ? " " : "!")
process.stdout.write(dec2hex((reader2_nr_enc >> 16) & 0xFF, 8))
process.stdout.write(oddParity8((reader2_nr >> 16) & 0xFF) ==
(oddParity8((reader2_nr_enc >> 16) & 0xFF) ^ ((reader2_ks1 >> 8) & 1)) ? " " : "!")
process.stdout.write(dec2hex((reader2_nr_enc >> 8) & 0xFF, 8))
process.stdout.write(oddParity8((reader2_nr >> 8) & 0xFF) ==
(oddParity8((reader2_nr_enc >> 8) & 0xFF) ^ ((reader2_ks1 >> 0) & 1)) ? " " : "!")
process.stdout.write(dec2hex((reader2_nr_enc >> 0) & 0xFF, 8))
process.stdout.write(oddParity8((reader2_nr >> 0) & 0xFF) ==
(oddParity8((reader2_nr_enc >> 0) & 0xFF) ^ (reader2_ks2 >> 24) & 1) ? " " : "!")

process.stdout.write(dec2hex((reader2_ar_enc >> 24) & 0xFF, 8))
process.stdout.write(oddParity8((reader2_ar >> 24) & 0xFF) ==
(oddParity8((reader2_ar_enc >> 24) & 0xFF) ^ ((reader2_ks2 >> 16) & 1)) ? " " : "!")
process.stdout.write(dec2hex((reader2_ar_enc >> 16) & 0xFF, 8))
process.stdout.write(oddParity8((reader2_ar >> 16) & 0xFF) ==
(oddParity8((reader2_ar_enc >> 16) & 0xFF) ^ ((reader2_ks2 >> 8) & 1)) ? " " : "!")
process.stdout.write(dec2hex((reader2_ar_enc >> 8) & 0xFF, 8))
process.stdout.write(oddParity8((reader2_ar >> 8) & 0xFF) ==
(oddParity8((reader2_ar_enc >> 8) & 0xFF) ^ ((reader2_ks2 >> 0) & 1)) ? " " : "!")
process.stdout.write(dec2hex((reader2_ar_enc >> 0) & 0xFF, 8))
process.stdout.write(oddParity8((reader2_ar >> 0) & 0xFF) ==
(oddParity8((reader2_ar_enc >> 0) & 0xFF) ^ reader2_ks_next_bit) ? " " : "!")
console.log()

let tag2_nr_enc = reader2_nr_enc;
let tag2_ar_enc = reader2_ar_enc;

let tag2_ks1 = crypto1_word(tag2_state, tag2_nr_enc, true);
console.log(`                                    ks1 = crypto1_word(s, {nR}, 1)        ${dec2hex(tag2_ks1, 32)}`)

let tag2_nr = tag2_ks1 ^ tag2_nr_enc;
console.log(`                                    nR = ks1 ^ {nR}                       ${dec2hex(tag2_nr, 32)}`)

let tag2_ks2 = crypto1_word(tag2_state, 0);
console.log(`                                    ks2 = crypto1_word(s, 0, 0)           ${dec2hex(tag2_ks2, 32)}`)

let tag2_ar = tag2_ks2 ^ tag2_ar_enc;
console.log(`                                    aR = ks2 ^ {aR}                       ${dec2hex(tag2_ar, 32)}`)

process.stdout.write("                                    aR == suc64(nT) ?                     ")
process.stdout.write(dec2hex(prng_successor(tag2_nt, 64), 32))
process.stdout.write(tag2_ar == prng_successor(tag2_nt, 64) ? " OK\n" : " FAIL\n")

let tag2_at = prng_successor(tag2_nt, 96);
console.log(`                                    aT = suc96(nT)                        ${dec2hex(tag2_at, 32)}`)

let tag2_ks3 = crypto1_word(tag2_state, 0);
console.log(`                                    ks3 = crypto1_word(s, 0, 0)           ${dec2hex(tag2_ks3, 32)}`)

let tag2_ks4 = crypto1_word(tag2_state, 0);
console.log(`                                    ks4 = crypto1_word(s, 0, 0)           ${dec2hex(tag2_ks4, 32)}`)

let tag2_at_enc = tag2_ks3 ^ tag2_at;
console.log(`                                    {aT} = ks3 ^ aT                       ${dec2hex(tag2_at_enc, 32)}`)

process.stdout.write(`                                 <- {aT}                                < `)
process.stdout.write(dec2hex((tag2_at_enc >> 24) & 0xFF, 8))
process.stdout.write(oddParity8((tag2_at >> 24) & 0xFF) ==
(oddParity8((tag2_at_enc >> 24) & 0xFF) ^ ((tag2_ks3 >> 16) & 1)) ? " " : "!")
process.stdout.write(dec2hex((tag2_at_enc >> 16) & 0xFF, 8))
process.stdout.write(oddParity8((tag2_at >> 16) & 0xFF) ==
(oddParity8((tag2_at_enc >> 16) & 0xFF) ^ ((tag2_ks3 >> 8) & 1)) ? " " : "!")
process.stdout.write(dec2hex((tag2_at_enc >> 8) & 0xFF, 8))
process.stdout.write(oddParity8((tag2_at >> 8) & 0xFF) ==
(oddParity8((tag2_at_enc >> 8) & 0xFF) ^ ((tag2_ks3 >> 0) & 1)) ? " " : "!")
process.stdout.write(dec2hex((tag2_at_enc >> 0) & 0xFF, 8))
process.stdout.write(oddParity8((tag2_at >> 0) & 0xFF) ==
(oddParity8((tag2_at_enc >> 0) & 0xFF) ^ (tag2_ks4 >> 24) & 1) ? " " : "!")
console.log()

let reader2_at_enc = tag2_at_enc;
let reader2_ks3 = crypto1_word(reader2_state, 0);

console.log(`ks3 = crypto1_word(s, 0, 0)                                               ${dec2hex(reader2_ks3, 32)}`)

let reader2_at = reader2_ks3 ^ reader2_at_enc;
console.log(`aT = ks3 ^ {aT}                                                           ${dec2hex(reader2_at, 32)}`)
console.log(`aT == suc96(nT) ?                                                         ${dec2hex(prng_successor(reader2_nt, 96), 32)} ${reader2_at == prng_successor(tag2_nt, 96) ? "OK" : "FAIL"}`)