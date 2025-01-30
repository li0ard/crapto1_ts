# crapto1_ts

Crapto1 C# implement. Recovery keys for MIFARE Classic in TypeScript!

## Installation

```bash
# from NPM
npm i @li0ard/crapto1_ts

# from JSR
bunx i jsr install @li0ard/crapto1-ts
```

## Usage

### Recovery by 2 sets of 32 bit auth
```ts
import { recovery32 } from "@li0ard/crapto1_ts" // or @li0ard/crapto1-ts

console.log(recovery32(
    uid,
    tagChallenge,
    readerChallenge,
    readerResponse,
    tagChallenge2,
    readerChallenge2,
    readerResponse2
).toString(16))
```