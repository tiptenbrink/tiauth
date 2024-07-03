import fs from 'node:fs'
import { pack } from 'msgpackr';

import { initSync, createSetClaimsProof, createProofKey } from './out/tiauth_app_js.js'
const data = fs.readFileSync('./out/tiauth_app_js_bg.wasm');
initSync(data)


// const private_pem = `
// -----BEGIN PRIVATE KEY-----
// MEcCAQAwBQYDK2VxBDsEOS36kRwunFManth6OjtbK7ywRMfPcPZ8JMKtiV97eluq
// DOT6DnnZsSGCwyOpmb+Ke5+PN42Du+J39g==
// -----END PRIVATE KEY-----
// `.trim()
const private_pem = `
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIDOQyFXRlMQuTiQ9vFBc5qBXG1U2p79Qa0l40jO+Qlr/
-----END PRIVATE KEY-----
`.trim()


const count = 10
let total = 0
let proofs = []

let size = 800000;
let ob_len = size/18;

let ob_entries = []

for (let j = 0; j < ob_len; j++) {
    let arr = []
    for (let k = 0; k < 8; k++) {
        let n = Math.random()
        let n_i = (n * 1000000) % 256
        arr.push(n_i)
    }
    let n_arr = new Uint8Array(arr)
    let n = Math.random()
    let n_str = `${n}`.slice(0,12)
    ob_entries.push([n_str, n_arr])
}

let encoder = new TextEncoder()

ob_entries.sort((a, b) => {
    // @ts-ignore
    let a_enc = encoder.encode(a[0])
    // @ts-ignore
    let b_enc = encoder.encode(b[0])

    return a_enc > b_enc ? 1 : -1
})

let ob = Object.fromEntries(ob_entries)

let bin = pack(ob)
console.log(`size ${bin.byteLength/1000} kB`)

// let utf8Encode = new TextEncoder();
// let cursor = 0
// let uarr = new Uint8Array(1000000)

// for (let j = 0; cursor < uarr.length - 1000; j++) {
//     let arr = []
//     for (let k = 0; k < 10; k++) {
//         let n = Math.random()
//         let n_i = (n * 10000) % 32
//         arr.push(n_i)
//     }
//     let n = Math.random()
//     let n_arr = new Uint8Array(arr)
//     let n_str = `${n}`.slice(0, 12)
//     let enc = utf8Encode.encode(n_str)

//     uarr.set(enc, cursor)
//     uarr.set(n_arr, cursor+enc.length)
//     cursor += enc.length + n_arr.length
// }

const key = createProofKey(private_pem)

// console.log(ob)

for (let i = 0; i < count; i++) {
    const msStart =  performance.now()
    //const proof = createResetProof("some_app", key, "abc7")
    const proof = createSetClaimsProof("some_app", key, "abc7", ob)
    //const proof = createSetClaimsProofBytes("some_app", key, "abc7", uarr)
    // const proof = createSetClaimsProof("some_app", key, "abc7", { "some_key": "my_claim" })
    const msEnd =  performance.now()
    total += (msEnd - msStart)
    proofs.push(proof)
}

console.log(`Time: ${total/count} ms.`)

const proof_str = proofs.toString()
console.log(`${proof_str.slice(0, 15)}...`)
