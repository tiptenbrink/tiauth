from typing import Literal
from httpx import Client as _Client
from msgspec import json as _json
import opaquepy.lib as _opq

import tiauth_app_py.app as _app
import tiauth_app_py.model as _model
from tiauth_app_py.app import Claims, ClaimsBytes

class TiauthClient:
    application: str
    json_client: _Client
    proof_key: _app.ProofKey

    def __init__(self, url: str, application_name: str, private_key_pem: str):
        self.json_client = _Client(base_url=url, headers={'content-type': 'application/json'})
        self.application = application_name
        self.proof_key = _app.load_key_from_pem(private_key_pem)

    def register_user(self, user_id: str, password: str, claims: Claims | ClaimsBytes | None = None):
        start_request, state = _opq.register_client(password)
        req = _model.PakeRequest(self.application, start_request, user_id)
        r = self.json_client.post("/register/start", content=_json.encode(req))

        pake_response = _json.decode(r.content, type=_model.PakeResponse)

        if claims is not None:
            proof = _app.create_set_claims_proof(self.application, self.proof_key, user_id, claims)
        else:
            proof = None

        request = _opq.register_client_finish(state, password, pake_response.opaque_response)
        req = _model.RegisterFinishRequest(self.application, request, pake_response.start_nonce, claims_proof=proof)

        r = self.json_client.post("/register/finish", content=_json.encode(req))

        assert r.status_code == 200

    def login_user(self, user_id: str, password: str, claim_subset: list[str] | Literal["all"]):
        claim_subset = list(sorted(claim_subset))

        start_request, state = _opq.login_client(password)
        req = _model.PakeRequest(self.application, start_request, user_id)
        r = self.json_client.post("/login/start", content=_json.encode(req))

        pake_response = _json.decode(r.content, type=_model.PakeResponse)

        requested_claims: list[str] | None = None
        if claim_subset == "all":
            all_claims = True
        else:
            all_claims = None
            requested_claims = claim_subset

        request, secret = _opq.login_client_finish(state, password, pake_response.opaque_response)
        req = _model.LoginFinishRequest(self.application, request, pake_response.start_nonce, secret, all_claims, requested_claims)

        r = self.json_client.post("/login/session", content=_json.encode(req))

        assert r.status_code == 200

    