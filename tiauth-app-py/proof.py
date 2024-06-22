from tiauth_app_py import create_set_claims_proof, create_claims, create_reset_proof
from time import perf_counter
from base64 import urlsafe_b64encode, urlsafe_b64decode

private = """
-----BEGIN PRIVATE KEY-----
MEcCAQAwBQYDK2VxBDsEOS36kRwunFManth6OjtbK7ywRMfPcPZ8JMKtiV97eluq
DOT6DnnZsSGCwyOpmb+Ke5+PN42Du+J39g==
-----END PRIVATE KEY-----
""".strip()

def add_base64_padding(unpadded: str) -> str:
    while len(unpadded) % 4 != 0:
        unpadded += "="
    return unpadded

def proof_creation() -> bytes:
    

    time_start = perf_counter()
    # claims = create_claims({"hi": b'hi2'})
    # claims_enc = urlsafe_b64encode(claims).decode('utf-8').rstrip('=')
    # print(type(claims))
    proof = create_reset_proof("some_app", private, "abc7")
    
    proof_b = urlsafe_b64decode(add_base64_padding(proof))
    # proof = create_set_claims_proof("some_app", private, "abc7", {"hi": b'abcd'})
    print(len(proof_b))
    time_end = perf_counter() - time_start
    print(f"time: {time_end*1000} ms.")
    # read_all_use = ReadAllProof()
    # proof_use = msgpack.encode(read_all_use)
    # return create_proof(proof_use, app, private, None)
    print(proof)
    print(proof_b)


proof_creation()