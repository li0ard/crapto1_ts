import { Crypto1State, lfsr_recovery64 } from "../src";

const getRandomInt = (min: number, max: number) => {
    min = Math.ceil(min);
    return Math.floor(Math.random() * (Math.floor(max) - min + 1)) + min;
}

const count = 10;
let succeeded = 0; 

console.time("Benchmark (lfsr_recovery64)")
for(let i = 0; i < count; i++) {
    const state = new Crypto1State(getRandomInt(1000, 9999), getRandomInt(1000, 9999));
    const r = lfsr_recovery64(state.word(), state.word())[0];
    if ((r.odd << 8 == state.odd << 8) && (r.even << 8 == state.even << 8)) succeeded++;
}
console.timeEnd("Benchmark (lfsr_recovery64)")
console.log(`Succeeded ${succeeded}/${count}`)