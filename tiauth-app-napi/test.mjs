import { createResetProof, createSetClaimsProof } from './index.js'
 
const key = `
-----BEGIN PRIVATE KEY-----
MEcCAQAwBQYDK2VxBDsEOS36kRwunFManth6OjtbK7ywRMfPcPZ8JMKtiV97eluq
DOT6DnnZsSGCwyOpmb+Ke5+PN42Du+J39g==
-----END PRIVATE KEY-----
`.trim()

const count = 1000
let total = 0
let proofs = []

for (let i = 0; i < count; i++) {
    const msStart =  performance.now()
    const proof = createSetClaimsProof("some_app", key, "abc7", {"my_claim": "is_cool"})
    const msEnd =  performance.now()
    total += (msEnd - msStart)
    proofs.push(proof)
}

console.log(`Time: ${total/count} ms.`)

const proof_str = proofs.toString()
console.log(`${proof_str.slice(0, 15)}...`)
