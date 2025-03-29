import fs from "fs"
import { recovery32 } from "../src";

if (process.argv.length < 3) {
    console.log('Usage: [bun/node] ' + process.argv[1] + ' /path/to/.mfkey32.log')
    console.log('Example: [bun/node] mfkey32_flipper.ts .mfkey32.log')
    process.exit(1)
}

const nonces = new TextDecoder().decode(fs.readFileSync(process.argv[2])).split('\n')
if (nonces[nonces.length - 1]!.length === 0) {
    nonces.pop()
}

const keys = new Set<string>()
for (let i = 0; i < nonces.length; i++) {
    const args = nonces[i]!.slice(nonces[i]!.indexOf('cuid')).split(' ').filter((e, i) => i % 2 === 1)
    console.log(`Cracking nonce ${i + 1} of ${nonces.length}`)
    const key = recovery32(
        parseInt(args[0], 16),
        parseInt(args[1], 16),
        parseInt(args[2], 16),
        parseInt(args[3], 16),
        parseInt(args[4], 16),
        parseInt(args[5], 16),
        parseInt(args[6], 16),
    )
    if(key !== -1n) {
        keys.add(key.toString(16).padStart(12, "0"))
    }
}

console.log(`\nKeys: ${keys.size != 0 ? Array.from(keys).join(", ") : "-"}`)