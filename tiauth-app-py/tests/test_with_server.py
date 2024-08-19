from base64 import urlsafe_b64decode
from dataclasses import dataclass
from typing import Generator
from uuid import uuid4
from httpx import Client, Response
from opaquepy import register_client, register_client_finish
from opaquepy.lib import login_client, login_client_finish
import pytest
from msgspec import json, msgpack
import random

from tiauth_app_py.app import ProofToken, load_key_from_pem, public_from_private_key_pem, proof_token_from_bytes, create_read_all_proof
from tiauth_app_py.app import AppClient, UserClient, ApplicationLogin, ApplicationRegister
from tiauth_app_py.model import GetUsers, LoginFinishRequest, PakeRequest, PakeResponse, ProofTokenRequest, ProofTokenResponse, RegisterFinishRequest, SessionResponse, UserList, UserPasswords

TIAUTH_URL = "http://localhost:3000"
GOV_URL = "http://localhost:3001"

@pytest.fixture(scope="module")
def json_client() -> Generator[Client, None, None]:
    yield Client(base_url=TIAUTH_URL, headers={'content-type': 'application/json'})

@pytest.fixture(scope="module")
def gov_client() -> Generator[Client, None, None]:
    yield Client(base_url=GOV_URL)


@pytest.fixture(scope="module", autouse=True)
def mod_app(gov_client: Client) -> Generator[str, None, None]:
    n = random.randint(0, 1000000000)
    app_name = f"app_{n}"

    gov_client.post(f"/load/{app_name}", content=public.encode('utf-8'))

    yield app_name

    gov_client.post(f"/delete/{app_name}")

@pytest.fixture
def once_app(gov_client: Client) -> Generator[str, None, None]:
    n = random.randint(0, 1000000000)
    app_name = f"app_{n}"

    gov_client.post(f"/load/{app_name}", content=public.encode('utf-8'))

    yield app_name

    gov_client.post(f"/delete/{app_name}")

@dataclass
class RegisteredUser:
    user_id: str
    password: str

def make_registered_user(json_client: Client, app_name: str, user_id: str, password: str) -> RegisteredUser:
    request, state = register_client(password)
    req = PakeRequest(app_name, request, user_id)
    r = json_client.post("/register/start", content=json.encode(req))

    if r.status_code != 200 or r.headers['content-type'] != 'application/json':
        raise ValueError(r.text)

    res = json.decode(r.content, type=PakeResponse)
    request = register_client_finish(state, password, res.opaque_response)

    req = RegisterFinishRequest(app_name, request, res.start_nonce)
    r = json_client.post("/register/finish", content=json.encode(req))

    if r.status_code != 200:
        raise ValueError(r.text)
    
    return RegisteredUser(user_id, password)


@pytest.fixture
def registered_user(json_client: Client, mod_app: str) -> Generator[RegisteredUser, None, None]:
    user_id = str(uuid4())
    password = "my_pass"

    reg_user = make_registered_user(json_client, mod_app, user_id, password)

    yield reg_user

def test_register(registered_user: RegisteredUser):
    assert isinstance(registered_user, RegisteredUser)

@dataclass
class UserSession:
    user_id: str
    password: str
    session: str

def make_user_session(json_client: Client, registered_user: RegisteredUser, app_name: str) -> UserSession:
    request, state = login_client(registered_user.password)
    req = PakeRequest(app_name, request, registered_user.user_id)
    r = json_client.post("/login/start", content=json.encode(req))

    if r.status_code != 200 or r.headers['content-type'] != 'application/json':
        raise ValueError(r.text)

    res = json.decode(r.content, type=PakeResponse)
    request, secret = login_client_finish(state, registered_user.password, res.opaque_response)

    req = LoginFinishRequest(app_name, request, res.start_nonce, secret, True, None)
    r = json_client.post("/login/session", content=json.encode(req))

    if r.status_code != 200 or r.headers['content-type'] != 'application/json':
        raise ValueError(r.text)
    
    session_response = json.decode(r.content, type=SessionResponse)

    return UserSession(registered_user.user_id, registered_user.password, session_response.session)


@pytest.fixture
def user_session(json_client: Client, registered_user: RegisteredUser, mod_app: str) -> Generator[UserSession, None, None]:
    sess = make_user_session(json_client, registered_user, mod_app)
    
    yield sess

def test_login(user_session: UserSession):
    assert len(user_session.session) > 0

def make_user_client(app_name: str):
    return UserClient(app_name, TIAUTH_URL)

def make_app_client(app_name: str):
    return AppClient(app_name, TIAUTH_URL, private)

@pytest.fixture(scope="module")
def app_client(mod_app: str):
    yield make_app_client(mod_app)

@pytest.fixture
def app_client_once(once_app: str):
    yield make_app_client(once_app)

@pytest.fixture(scope="module")
def user_client(mod_app: str):
    yield make_user_client(mod_app)

@pytest.fixture
def user_client_once(once_app: str):
    yield make_user_client(once_app)


def test_client_login(app_client: AppClient, user_client: UserClient, registered_user: RegisteredUser):
    login = app_client.prepare_login(registered_user.user_id)

    session = user_client.login_user(login, registered_user.password)
    
    assert len(session) > 0


def test_client_register(app_client: AppClient, user_client: UserClient, json_client: Client, mod_app: str):
    user_id = str(uuid4())
    password = "my_pass"

    register = app_client.prepare_register(user_id)

    user_client.register_user(register, password)

    registered_user = RegisteredUser(user_id, password)

    make_user_session(json_client, registered_user, mod_app)


def dec_b64url(s: str) -> bytes:
    while len(s) % 4 != 0:
        s += "="
    return urlsafe_b64decode(s.encode("utf-8"))


def make_proof_token(json_client: Client, app_name: str) -> ProofToken:
    req = ProofTokenRequest(app_name)

    r: Response = json_client.post("/proof/token", content=json.encode(req))
    
    token_res = json.decode(r.content, type=ProofTokenResponse)
    token_bytes = dec_b64url(token_res.tokens)

    token = proof_token_from_bytes(token_bytes)

    return token


private = """
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIDOQyFXRlMQuTiQ9vFBc5qBXG1U2p79Qa0l40jO+Qlr/
-----END PRIVATE KEY-----
""".strip()

public = public_from_private_key_pem(private)

# def get_some_users(json_client: Client, users: list[str], app_name: str):
#     key = load_key_from_pem(private)

#     proof = create_read_some_proof(app_name, key, users)
#     req = GetUsers(app_name, proof, True)

#     r: Response = json_client.post("/admin/users", content=json.encode(req))

#     structs = msgpack.decode(r.content, type=UserList)

#     # user_ids: list[str] = []
#     for u_encoded in structs.users:
#         u = msgpack.decode(u_encoded, type=UserClaims)
#         # user_ids.append(u.user_id)

def get_all_users(json_client: Client, app_name: str, proof_token: ProofToken) -> list[str]:
    key = load_key_from_pem(private)

    proof = create_read_all_proof(app_name, key, proof_token)
    req = GetUsers(app_name, proof, True)

    r: Response = json_client.post("/admin/users", content=json.encode(req))

    structs = msgpack.decode(r.content, type=UserList)

    user_ids: list[str] = []
    for u_encoded in structs.users:
        u = msgpack.decode(u_encoded, type=UserPasswords)
        user_ids.append(u.user_id)

    return user_ids


def test_has_users(json_client: Client, once_app: str):
    user_1 = make_registered_user(json_client, once_app, "user1", "pass")
    user_2 = make_registered_user(json_client, once_app, "user2", "pass")
    proof_token = make_proof_token(json_client, once_app)
    user_ids = get_all_users(json_client, once_app, proof_token)

    assert len(user_ids) == 2
    assert user_1.user_id in user_ids
    assert user_2.user_id in user_ids

