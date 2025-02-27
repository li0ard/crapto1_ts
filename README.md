<p align="center">
    <a href="https://github.com/li0ard/crapto1_ts/">
        <img src="https://raw.githubusercontent.com/li0ard/crapto1_ts/main/.github/logo.png" alt="crapto1_ts logo" title="crapto1_ts" width="120" /><br>
    </a><br>
    <b>crapto1_ts</b><br>
    <b>Recovery keys for MIFARE Classic</b>
    <br>
    <a href="https://li0ard.is-cool.dev/crapto1_ts">docs</a>
    <br><br>
    <a href="https://github.com/li0ard/crapto1_ts/actions/workflows/test.yml"><img src="https://github.com/li0ard/crapto1_ts/actions/workflows/test.yml/badge.svg" /></a>
    <a href="https://github.com/li0ard/crapto1_ts/blob/main/LICENSE"><img src="https://img.shields.io/github/license/li0ard/crapto1_ts" /></a>
    <br>
    <a href="https://npmjs.com/package/@li0ard/crapto1_ts"><img src="https://img.shields.io/npm/v/@li0ard/crapto1_ts" /></a>
    <a href="https://jsr.io/@li0ard/crapto1-ts"><img src="https://jsr.io/badges/@li0ard/crapto1-ts" /></a>
    <br>
    <hr>
</p>

## Installation

```bash
# from NPM
npm i @li0ard/crapto1_ts

# from JSR
bunx i jsr install @li0ard/crapto1-ts
```

## Usage

> [!TIP]
> Ported mfkey64 and mfkey32 are placed [here](https://github.com/li0ard/crapto1_ts/tree/main/examples)

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

### Recovery by 1 set of full 64 bit auth
```ts
import { recovery64 } from "@li0ard/crapto1_ts" // or @li0ard/crapto1-ts

console.log(recovery64(
    uid,
    tagChallenge,
    readerChallenge,
    readerResponse,
    tagResponse
).toString(16))
```

## Links
- [crapto1](https://github.com/li0ard/crapto1) - Original version in C
- [Crapto1Sharp](https://github.com/kgamecarter/Crapto1Sharp) - Version in C#
- [mfkey32nested](https://github.com/RfidResearchGroup/proxmark3/blob/master/tools/mfc/card_reader/mfkey32nested.c) - Original version in C