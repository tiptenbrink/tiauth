import { createResetProof, createSetClaimsProof } from './index.js'
 
const key = `
-----BEGIN PRIVATE KEY-----
MEcCAQAwBQYDK2VxBDsEOS36kRwunFManth6OjtbK7ywRMfPcPZ8JMKtiV97eluq
DOT6DnnZsSGCwyOpmb+Ke5+PN42Du+J39g==
-----END PRIVATE KEY-----
`.trim()

console.log(createSetClaimsProof("some_app", key, "abc7", { something: "ab" }))

console.log(createResetProof("some_app", key, "abc7"))