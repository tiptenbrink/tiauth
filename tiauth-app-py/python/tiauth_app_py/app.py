import tiauth_app_py._internal as _internal
from tiauth_app_py.model import ClaimsBytes, Claims, ReadAllProof, ReadSomeProof, ReadRangeProof, ClaimsProof

ProofKey = _internal.ProofKey
ProofToken = _internal.ProofToken
ApplicationLogin = _internal.ApplicationLogin
ApplicationRegister = _internal.ApplicationRegister
AppClient = _internal.AppClient
UserClient = _internal.UserClient

def proof_token_from_bytes(token: bytes) -> ProofToken:
   return _internal.proof_token_from_bytes(token)

def create_private_key_pem() -> str:
   return  _internal.create_private_key_pem()

def public_from_private_key_pem(private_key_pem: str) -> str:
   return  _internal.public_from_private_key_pem(private_key_pem)

def load_key_from_pem(private_key_pem: str) -> ProofKey:
   return  _internal.load_key_from_pem(private_key_pem)

def create_set_claims_proof(application: str, key: ProofKey, token: ProofToken, user_id: str, claims: Claims | ClaimsBytes) -> ClaimsProof:
   return  _internal.create_set_claims_proof(application, key, token, user_id, claims)

# def create_reset_proof(application: str, key: ProofKey, user_id: str) -> ClaimsProof:
#    return  _internal.create_reset_proof(application, key, user_id)

def create_read_all_proof(application: str, key: ProofKey, token: ProofToken) -> ReadAllProof:
   return  _internal.create_read_all_proof(application, key, token)

# def create_read_some_proof(application: str, key: ProofKey, selection: list[str]) -> ReadSomeProof:
#    """`selection` is a sorted list of targets."""
#    return  _internal.create_read_some_proof(application, key, selection)

# def create_read_range_proof(application: str, key: ProofKey, selection: tuple[str, str]) -> ReadRangeProof:
#    """`selection` is a sorted list of targets."""
#    return  _internal.create_read_range_proof(application, key, list(selection))