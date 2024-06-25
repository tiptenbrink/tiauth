from .tiauth_app_py import _internal
from tiauth_app_py.model import Lazy, Claims, ReadAllProof, ClaimsProof

def create_private_key_pem() -> str:
   return  _internal.create_private_key_pem()

def public_from_private_key_pem(private_key_pem: str) -> str:
   return  _internal.public_from_private_key_pem(private_key_pem)

def create_set_claims_proof(application: str, private_key_pem: str, user_id: str, claims: Lazy[Claims]) -> str:
   return  _internal.create_set_claims_proof(application, private_key_pem, user_id, claims)

def create_reset_proof(application: str, private_key_pem: str, user_id: str) -> ClaimsProof:
   return  _internal.create_reset_proof(application, private_key_pem, user_id)

def create_read_all_proof(application: str, private_key_pem: str) -> ReadAllProof:
   return  _internal.create_read_all_proof(application, private_key_pem)
