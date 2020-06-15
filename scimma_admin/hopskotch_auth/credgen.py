from __future__ import annotations
from typing import Optional
import dataclasses
import base64
from passlib.hash import scram
import hmac
import hashlib
import enum


@dataclasses.dataclass
class SCRAMCredentials:
    salt: bytes
    stored_key: bytes
    server_key: bytes
    iterations: int

    def __init__(self, password: str, alg: SCRAMAlgorithm,
                 salt: Optional[bytes] = None, iterations: int = 4096):
        """ Generate SCRAM credentials, hashing the given password using the given algorithm."""
        if salt is None:
            salt = generate_salt()
        salted_pw = scram.derive_digest(password, salt=salt, rounds=iterations, alg=alg.value)

        hash_func = alg.hash_function()
        self.server_key = hmac.new(salted_pw, b"Server Key", hash_func).digest()
        client_key = hmac.new(salted_pw, b"Client Key", hash_func).digest()
        self.stored_key = hash_func(client_key).digest()
        self.salt = salt
        self.iterations = iterations

    def __eq__(self, other: SCRAMCredentials) -> bool:
        return (self.salt == other.salt
                and self.stored_key == other.stored_key
                and self.server_key == other.server_key
                and self.iterations == other.iterations)

    def serialize(self) -> bytes:
        """Emits the SCRAMCredentials as a Kafka-style base64-encoded sequence of
        keyval pairs."""
        parts = [
            b"salt=" + base64.b64encode(self.salt),
            b"stored_key=" + base64.b64encode(self.stored_key),
            b"server_key=" + base64.b64encode(self.server_key),
            b"iterations=" + str(self.iterations).encode("ascii")
        ]
        return b",".join(parts)

    @classmethod
    def deserialize(cls, raw: bytes) -> SCRAMCredentials:
        """Read the base64-encoded Kafka-style format."""
        parts = raw.split(b",")
        keyval = dict(p.split(b"=", 1) for p in parts)
        return SCRAMCredentials(
            salt=base64.decodebytes(keyval['salt']),
            stored_key=base64.decodebytes(keyval['stored_key']),
            server_key=base64.decodebytes(keyval['server_key']),
            iterations=int(keyval['iterations']),
        )


class SCRAMAlgorithm(enum.Enum):
    # Only two hash algorithms supported in Kafka
    SHA256 = "sha-256"
    SHA512 = "sha-512"

    def hash_function(self):
        if self == SCRAMAlgorithm.SHA256:
            return hashlib.sha256
        if self == SCRAMAlgorithm.SHA512:
            return hashlib.sha512
        raise NotImplementedError("unimplemented hash")
