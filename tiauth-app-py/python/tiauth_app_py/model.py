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
    register_start_nonce: str

type ClaimsProof = str
"""Proof obtained using `create_set_claims_proof`."""

class PakeFinishRequest(Struct):
    application: str
    opaque_request: str
    register_start_nonce: str
    claims_proof: Optional[ClaimsProof] = None

type ReadAllProof = str
"""Proof obtained using `create_read_all_proof`."""

class GetUsers(Struct):
    application: str
    read_all_proof: ReadAllProof

class StructList(Struct):
    list: list[bytes]