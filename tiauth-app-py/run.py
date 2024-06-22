from typing import Any, Optional
import httpx
from base64 import urlsafe_b64encode
from httpx import Response, Client
from msgspec import json, Struct, msgpack, Raw
from opaquepy import register_client, register_client_finish
from tiauth_app_py.model import PakeFinishRequest, PakeRequest, PakeResponse, GetUsers, StructList
from tiauth_app_py import create_set_claims_proof, create_read_all_proof

class Login(Struct):
    user_id: str
    password_file: str
    claims: bytes

app = "some_app"

private = """
-----BEGIN PRIVATE KEY-----
MEcCAQAwBQYDK2VxBDsEOS36kRwunFManth6OjtbK7ywRMfPcPZ8JMKtiV97eluq
DOT6DnnZsSGCwyOpmb+Ke5+PN42Du+J39g==
-----END PRIVATE KEY-----
""".strip()

json_client = Client(base_url="http://localhost:3000", headers={'content-type': 'application/json'})
APP_NAME = "some_app"

def get_users():
    proof = create_read_all_proof(APP_NAME, private)
    req = GetUsers(APP_NAME, proof)

    r: Response = json_client.post("/admin/users", content=json.encode(req))
    # print(r.content.decode('utf-8'))
    structs = msgpack.decode(r.content, type=StructList)

    for u_encoded in structs.list:
        print(msgpack.decode(u_encoded, type=Login))


def register_flow():
    user_id = "abc8"
    password = "my_password"

    request, state = register_client(password)

    request, state = register_client(password)
    req = PakeRequest(APP_NAME, request, user_id)
    r = json_client.post("/register/start", content=json.encode(req))

    if r.headers['content-type'] != 'application/json':
        raise ValueError(r.text)

    res = json.decode(r.content, type=PakeResponse)
    request = register_client_finish(state, password, res.opaque_response)

    proof = create_set_claims_proof(APP_NAME, private, user_id, {"my_claim": "is_cool"})

    req = PakeFinishRequest(APP_NAME, request, res.register_start_nonce, claims_proof=proof)
    r = json_client.post("/register/finish", content=json.encode(req))

    if r.status_code != 200:
        raise ValueError(r.text)

register_flow()

get_users()