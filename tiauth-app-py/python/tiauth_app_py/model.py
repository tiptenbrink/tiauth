from typing import Optional
from msgspec import msgpack, Struct

type Claims = dict[str, bytes | str]
"""Claims represent a map with string keys and bytes/string values. String values are encoded on the server as UTF-8. With this, arbitrary
claims about the user, as verified by the application, can be stored and later retrieved."""

type ClaimsBytes = bytes
"""Serialized Claims object."""

class PakeRequest(Struct):
    application: str
    opaque_request: str
    user_id: str

class PakeResponse(Struct):
    opaque_response: str
    start_nonce: str

type ClaimsProof = str
"""Proof obtained using `create_set_claims_proof`."""

class RegisterFinishRequest(Struct):
    application: str
    opaque_request: str
    start_nonce: str
    claims_proof: Optional[ClaimsProof] = None

type ReadAllProof = str
"""Proof obtained using `create_read_all_proof`."""

class GetUsers(Struct):
    application: str
    read_all_proof: ReadAllProof

class StructList(Struct):
    list: list[bytes]

class LoginFinishRequest(Struct):
    application: str
    opaque_request: str
    start_nonce: str
    pake_secret: str
    all_claims: Optional[bool]
    requested_claims: Optional[list[str]]

class SessionResponse(Struct):
    session: str