from typing import Optional
from .tiauth_app_py import _internal

def create_private_key_pem() -> str:
   return  _internal.create_private_key_pem()

def public_from_private_key_pem(private_key_pem: str) -> str:
   return  _internal.public_from_private_key_pem(private_key_pem)

def create_proof(proof_use: bytes, application: str, private_key_pem: str, expires_in: Optional[int]) -> bytes:
   return  _internal.create_proof(proof_use, application, private_key_pem, expires_in)