
class Proof:


    def as_bytes(self) -> bytes:
        return b''
    
    def as_str(self) -> str:
        return ''

from typing import Any, Optional, Self


class Claims:
    pass    


class ProofScope:
    _use_bytes: bytes


    def create_proof(self, application: str, private_key: str, expires: Optional[int] = None) -> Proof:
        proof = Proof()
    
    @classmethod
    def claims(cls, claims: dict[str, Any]) -> Self:
        proof_use = cls()
        proof_use._use_bytes = b''

        return proof_use
    

proof = create_proof()




