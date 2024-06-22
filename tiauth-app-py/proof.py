from tiauth_app_py import create_set_claims_proof, create_claims
from time import perf_counter
from base64 import urlsafe_b64encode

private = """
-----BEGIN PRIVATE KEY-----
MEcCAQAwBQYDK2VxBDsEOS36kRwunFManth6OjtbK7ywRMfPcPZ8JMKtiV97eluq
DOT6DnnZsSGCwyOpmb+Ke5+PN42Du+J39g==
-----END PRIVATE KEY-----
""".strip()

def proof_creation() -> bytes:
    

    time_start = perf_counter()
    # claims = create_claims({"hi": b'hi2'})
    # claims_enc = urlsafe_b64encode(claims).decode('utf-8').rstrip('=')
    # print(type(claims))
    proof = create_set_claims_proof("some_app", private, "abc7", {"hi": 42})

    time_end = perf_counter() - time_start
    print(f"time: {time_end*1000} ms.")
    # read_all_use = ReadAllProof()
    # proof_use = msgpack.encode(read_all_use)
    # return create_proof(proof_use, app, private, None)
    print(proof)


proof_creation()