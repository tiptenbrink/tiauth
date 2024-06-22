from typing import Optional
from .tiauth_app_py import _internal

def create_private_key_pem() -> str:
   return  _internal.create_private_key_pem()

def public_from_private_key_pem(private_key_pem: str) -> str:
   return  _internal.public_from_private_key_pem(private_key_pem)

type Lazy[T] = T | str | bytes
"""The Lazy type represents a potentially serialized version of the inner type. Provide either the type itself or the serialized variant
(either as bytes or base64url-encoded string) received from another function."""

# fn create_set_claims_proof(application: &str, private_key_pem: &str, user_id: &str, claims: LazyArg<Claims>) -> PyResult<String>
def create_set_claims_proof(application: str, private_key_pem: str, user_id: str, claims: Lazy[dict[str, bytes]]) -> bytes:
   return  _internal.create_set_claims_proof(application, private_key_pem, user_id, claims)

def create_claims(claims: dict[str, bytes] | str | bytes) -> bytes:
   return  _internal.create_claims(claims)

# def create_proof(proof_use: bytes, application: str, private_key_pem: str, expires_in: Optional[int]) -> bytes:
#    return  _internal.create_proof(proof_use, application, private_key_pem, expires_in)