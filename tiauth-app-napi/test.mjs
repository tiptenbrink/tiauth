import { createResetProof, createSetClaimsProof, createProofKey } from './index.js'
 
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


const count = 10000
let total = 0
let proofs = []

let size = 18;
let ob_len = size/18;

let ob = {}

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
    ob[n_str] = n_arr
}

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
