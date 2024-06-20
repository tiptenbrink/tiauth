from typing import Any, Optional
import httpx
from base64 import urlsafe_b64encode
from httpx import Response, Client
from msgspec import json, Struct, msgpack, Raw
from opaquepy import register_client, register_client_finish
from tiauth_app_py import create_private_key_pem, create_proof, public_from_private_key_pem

class PakeRequest(Struct):
    application: str
    user_id: str
    request: str

class PakeResponse(Struct):
    response: str
    nonce: str

class PakeFinishRequest(Struct, kw_only=True):
    application: str
    request: str
    nonce: str
    claims: Optional[str] = None

class ProofUse(Struct):
    use: str

class ReadAllProof(ProofUse):
    use: str = "ReadAll"

class SetClaims(ProofUse, kw_only=True):
    use: str = "SetClaims"
    user_id: str
    claims: dict[str, Any]
    
class StructList(Struct):
    list: list[bytes]

class Login(Struct):
    user_id: str
    password_file: str
    claims: dict[str, Any]

app = "some_app"

private = """
-----BEGIN PRIVATE KEY-----
MEcCAQAwBQYDK2VxBDsEOS36kRwunFManth6OjtbK7ywRMfPcPZ8JMKtiV97eluq
DOT6DnnZsSGCwyOpmb+Ke5+PN42Du+J39g==
-----END PRIVATE KEY-----
""".strip()

def proof_creation() -> bytes:
    # private = create_private_key_pem()
    # print(private)
    # print(public_from_private_key_pem(private))
    read_all_use = ReadAllProof()
    proof_use = msgpack.encode(read_all_use)
    return create_proof(proof_use, app, private, None)

def proof_creation_claims() -> bytes:
    set_claims_use = SetClaims(user_id="abc5", claims={"email": "abc4@abc.nl", "other": "hi"})
    proof_use = msgpack.encode(set_claims_use)
    return create_proof(proof_use, app, private, None)

def get_users():
    json_client = Client(base_url="http://localhost:3000", headers={'content-type': 'application/json'})
    proof = proof_creation()
    r: Response = json_client.post("/admin/users", content=proof)
    structs = msgpack.decode(r.content, type=StructList)

    for u_encoded in structs.list:
        print(msgpack.decode(u_encoded, type=Login))


def register_flow():
    user_id = "abc5"
    password = "my_password"

    request, state = register_client(password)

    json_client = Client(base_url="http://localhost:3000", headers={'content-type': 'application/json'})

    r = json_client.post("/register/start", content=json.encode(PakeRequest(app, user_id, request)))

    if r.headers['content-type'] != 'application/json':
        raise ValueError(r.text)

    res = json.decode(r.content, type=PakeResponse)

    print(res)

    request = register_client_finish(state, password, res.response)

    proof = proof_creation_claims()
    proof_b64 = urlsafe_b64encode(proof).decode('utf-8').rstrip('=')

    r = json_client.post("/register/finish", content=json.encode(PakeFinishRequest(application=app, request=request, nonce=res.nonce, claims=proof_b64)))

    print(r.status_code)

register_flow()

get_users()