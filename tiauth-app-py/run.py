from typing import Any, Optional
import httpx
from base64 import urlsafe_b64encode
from httpx import Response, Client
from msgspec import json, Struct, msgpack, Raw
from opaquepy import register_client, register_client_finish
from tiauth_app_py.model import RegisterFinishRequest, PakeRequest, PakeResponse, GetUsers, User, UserList, UserClaims
from tiauth_app_py import create_set_claims_proof, create_read_all_proof, create_reset_proof, load_key_from_pem, public_from_private_key_pem
from tiauth_app_py.app import create_read_range_proof, create_read_some_proof
import tiauth_app_py
from time import perf_counter
import random

class Login(Struct, array_like=True):
    user_id: str
    password_file: str
    claims: bytes

app = "some_app"
private = """
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIDOQyFXRlMQuTiQ9vFBc5qBXG1U2p79Qa0l40jO+Qlr/
-----END PRIVATE KEY-----
""".strip()
# private = """
# -----BEGIN PRIVATE KEY-----
# MEcCAQAwBQYDK2VxBDsEOS36kRwunFManth6OjtbK7ywRMfPcPZ8JMKtiV97eluq
# DOT6DnnZsSGCwyOpmb+Ke5+PN42Du+J39g==
# -----END PRIVATE KEY-----
# """.strip()

json_client = Client(base_url="http://localhost:3000", headers={'content-type': 'application/json'})
APP_NAME = "some_app"

def get_all_users():
    key = load_key_from_pem(private)

    proof = create_read_all_proof(APP_NAME, key)
    req = GetUsers(APP_NAME, proof, None)

    r: Response = json_client.post("/admin/users", content=json.encode(req))
    # print(r.content.decode('utf-8'))
    structs = msgpack.decode(r.content, type=UserList)

    for u_encoded in structs.users:
        print(msgpack.decode(u_encoded, type=User))


def get_some_users(users: list[str]):
    key = load_key_from_pem(private)

    proof = create_read_some_proof(APP_NAME, key, users)
    req = GetUsers(APP_NAME, proof, True)

    r: Response = json_client.post("/admin/users", content=json.encode(req))
    # print(r.content.decode('utf-8'))
    structs = msgpack.decode(r.content, type=UserList)

    for u_encoded in structs.users:
        print(msgpack.decode(u_encoded, type=UserClaims))

def get_range_users(user_range: tuple[str, str]):
    key = load_key_from_pem(private)

    proof = create_read_range_proof(APP_NAME, key, user_range)
    req = GetUsers(APP_NAME, proof, True)

    r: Response = json_client.post("/admin/users", content=json.encode(req))
    # print(r.content.decode('utf-8'))
    structs = msgpack.decode(r.content, type=UserList)

    for u_encoded in structs.users:
        print(msgpack.decode(u_encoded, type=UserClaims))


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

def proof_time():
    ob_keys: list[str] = []
    ob_values: list[bytes] = []
    d_size = 1000000
    for i in range(int(d_size/20)):
        val = random.random()
        a = bytes([random.randint(0, 255) for j in range(8)])
        k_str = f"{val}"[0:12]
        ob_keys.append(k_str)
        ob_values.append(a)

    ob_keys = sorted(ob_keys)
    ob = {k: ob_values[i] for i, k in enumerate(ob_keys)}

    ob_encode = msgpack.encode(ob)
    print(f"size: {len(ob_encode)/1000} kB")
    # ob = ob_encode

    proof_key = tiauth_app_py.tiauth_app_py._internal.create_key(private)
    count = 10
    proofs = []
    total = 0
    for i in range(count):
        # obb = msgpack.encode(ob)
        time_start = perf_counter()
        # proof = tiauth_app_py.tiauth_app_py._internal.create_reset_proof_key(APP_NAME, proof_key, "user")
        # proof = create_reset_proof(APP_NAME, proof_key, "abc8")
        proof = create_set_claims_proof(APP_NAME, proof_key, "abc7", ob)
        time_end = perf_counter()
        proofs.append(proof)
        total += time_end - time_start
    # proof2 = create_set_claims_proof(APP_NAME, private, "abc20", {"my_claim": "is_cool"})
    # proof3 = create_set_claims_proof(APP_NAME, private, "abc20", {"my_claim": "is_cool"})
    # proof4 = create_set_claims_proof(APP_NAME, private, "abc20", {"my_claim": "is_cool"})
    # time_last = perf_counter()
    proofs = str(proofs)
    print(f"{total*1000/count} ms.")
    print(f"{proofs[:15]}...")

# proof_time()
    
# print(public_from_private_key_pem(private))
    
#get_all_users()

# get_some_users(['f228bfbe-30a7-4ab0-813a-b39c4a57dcb1'])
    
def create_app():
    gov_client = Client(base_url="http://localhost:3001")

    public = public_from_private_key_pem(private)

    # r = gov_client.post(f"/register/cool_app3", content=public.encode('utf-8'))

    r = gov_client.post(f"/deregister/cool_app3")

    print(r.status_code)
    print(r.content)

# get_range_users(('3', 'b'))

# print(create_private_key_pem())

# register_flow()

# get_users()
    
create_app()