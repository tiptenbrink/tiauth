from dataclasses import dataclass
from typing import Generator
from uuid import uuid4
from httpx import Client
from opaquepy import register_client, register_client_finish
from opaquepy.lib import login_client, login_client_finish
import pytest
from msgspec import json

from tiauth_app_py.model import LoginFinishRequest, PakeRequest, PakeResponse, RegisterFinishRequest, SessionResponse


APP_NAME = "some_app"
SERVER_URL = "http://localhost:3000"

@pytest.fixture
def json_client() -> Generator[Client, None, None]:
    yield Client(base_url="http://localhost:3000", headers={'content-type': 'application/json'})


@dataclass
class RegisteredUser:
    user_id: str
    password: str

@pytest.fixture
def registered_user(json_client: Client) -> Generator[RegisteredUser, None, None]:
    user_id = str(uuid4())
    password = "my_password"

    request, state = register_client(password)
    req = PakeRequest(APP_NAME, request, user_id)
    r = json_client.post("/register/start", content=json.encode(req))

    if r.status_code != 200 or r.headers['content-type'] != 'application/json':
        raise ValueError(r.text)

    res = json.decode(r.content, type=PakeResponse)
    request = register_client_finish(state, password, res.opaque_response)

    req = RegisterFinishRequest(APP_NAME, request, res.start_nonce)
    r = json_client.post("/register/finish", content=json.encode(req))

    if r.status_code != 200:
        raise ValueError(r.text)
    
    yield RegisteredUser(user_id, password)


def test_register(registered_user: RegisteredUser):
    assert isinstance(registered_user, RegisteredUser)

@dataclass
class UserSession:
    user_id: str
    password: str
    session: str

@pytest.fixture
def user_session(json_client: Client, registered_user: RegisteredUser) -> Generator[UserSession, None, None]:
    request, state = login_client(registered_user.password)
    req = PakeRequest(APP_NAME, request, registered_user.user_id)
    r = json_client.post("/login/start", content=json.encode(req))

    if r.status_code != 200 or r.headers['content-type'] != 'application/json':
        raise ValueError(r.text)

    res = json.decode(r.content, type=PakeResponse)
    request, secret = login_client_finish(state, registered_user.password, res.opaque_response)

    req = LoginFinishRequest(APP_NAME, request, res.start_nonce, secret, True, None)
    r = json_client.post("/login/session", content=json.encode(req))

    if r.status_code != 200 or r.headers['content-type'] != 'application/json':
        raise ValueError(r.text)
    
    session_response = json.decode(r.content, type=SessionResponse)
    
    yield UserSession(registered_user.user_id, registered_user.password, session_response.session)

def test_login(user_session: UserSession):
    assert len(user_session.session) > 0