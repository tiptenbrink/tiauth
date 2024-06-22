from typing import Generator
from uuid import uuid4
from httpx import Client
from opaquepy import register_client, register_client_finish
import pytest
from msgspec import json

from tiauth_app_py.model import PakeRequest, PakeResponse, PakeFinishRequest


APP_NAME = "some_app"
SERVER_URL = "http://localhost:3000"

@pytest.fixture
def json_client() -> Generator[None, None, Client]:
    yield Client(base_url="http://localhost:3000", headers={'content-type': 'application/json'})

def test_register_flow(json_client: Client):
    user_id = str(uuid4())
    password = "my_password"

    request, state = register_client(password)
    req = PakeRequest(APP_NAME, request, user_id)
    r = json_client.post("/register/start", content=json.encode(req))

    if r.headers['content-type'] != 'application/json':
        raise ValueError(r.text)

    res = json.decode(r.content, type=PakeResponse)
    request = register_client_finish(state, password, res.opaque_response)

    req = PakeFinishRequest(APP_NAME, request, res.register_start_nonce)
    r = json_client.post("/register/finish", content=json.encode(req))

    if r.status_code != 200:
        raise ValueError(r.text)