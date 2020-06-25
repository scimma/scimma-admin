from __future__ import annotations

from typing import Optional

from django.db import models
from django.conf import settings
from django_enumfield import enum
import hashlib
import uuid
import base64
from passlib.hash import scram
from passlib.utils import saslprep
import hmac
import hashlib


class KafkaIdentity(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    username = models.CharField(max_length=256, unique=True)  # Limit chosen pretty arbitrarily.
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
    )

class SCRAMAlgorithm(enum.Enum):
    SHA256 = 1
    SHA512 = 2

    def hash_function(self):
        """Return a hashlib hasher for the hash algorithm. """
        if self == SCRAMAlgorithm.SHA256:
            return hashlib.sha256
        if self == SCRAMAlgorithm.SHA512:
            return hashlib.sha512
        raise NotImplementedError("unimplemented hash")

    def iana_name(self):
        """Return the IANA text name of the hash, as per RFC8122.
        (http://www.iana.org/assignments/hash-function-text-names/hash-function-text-names.xhtml)
        """
        if self == SCRAMAlgorithm.SHA256:
            return "sha-256"
        if self == SCRAMAlgorithm.SHA512:
            return "sha-512"
        NotImplementedError("unimplemented hash")


class SCRAMCredentials(models.Model):
    user = models.ForeignKey(
        "KafkaIdentity",
        on_delete=models.CASCADE,
        editable=False,
    )
    # The SCRAM hashing algorithm used, as defined in RFC5802.
    algorithm = enum.EnumField(
        SCRAMAlgorithm,
        editable=False,
    )
    # The SCRAM 'Salt' as defined in RFFC5802.
    salt = models.BinaryField(
        max_length=128,
        editable=False,
    )
    # The SCRAM 'ServerKey' as defined in RFC5802.
    server_key = models.BinaryField(
        max_length=256,
        editable=False,
    )
    # The SCRAM 'StoredKey' as defined in RFC5802.
    stored_key = models.BinaryField(
        max_length=256,
        editable=False,
    )
    # The text representation of credentials used by Kafka.
    string_encoding = models.TextField(
        editable=False,
    )
    # The number of hash iterations used as defined in RFC5802.
    iterations = models.IntegerField(
        editable=False,
    )

    created_at = models.DateTimeField(auto_now_add=True)

    @classmethod
    def generate(cls, password: str, user: KafkaIdentity, alg: SCRAMAlgorithm,
                 salt: Optional[bytes] = None, iterations: int = 4096):

        """ Generate SCRAM credentials, hashing the given password using the given algorithm.

        If salt is unset, a random one is used.

        If iterations is unset, 4096 (the Kafka default) is used.
        """
        # Set number of rounds:
        scram_hasher = scram.using(rounds=iterations)
        # Set salt:
        if salt is not None:
            scram_hasher = scram_hasher.using(salt=salt)
        # Set algorithm (sha-1 must always be in the algorithm list):
        scram_hasher = scram_hasher.using(f"sha-1,{alg.iana_name()}")
        # Run the hash, taking care to normalize the password
        scram_hash = scram_hasher.hash(saslprep(password))
        salt, _, hashed_pw = scram.extract_digest_info(scram_hash, alg.iana_name())

        hash_func = alg.hash_function()
        server_key = hmac.new(hashed_pw, b"Server Key", hash_func).digest()
        client_key = hmac.new(hashed_pw, b"Client Key", hash_func).digest()
        stored_key = hash_func(client_key).digest()

        val = cls(
            algorithm=alg,
            salt=salt,
            server_key=server_key,
            stored_key=stored_key,
            iterations=iterations,
            string_encoding=cls.string_encode(salt, stored_key, server_key, iterations),
        )
        return val

    @staticmethod
    def string_encode(salt, stored_key, server_key, iterations) -> bytes:
        """Emits the SCRAMCredentials as a Kafka-style base64-encoded sequence of ASCII
        keyval pairs.

        """
        parts = [
            b"salt=" + base64.b64encode(salt),
            b"stored_key=" + base64.b64encode(stored_key),
            b"server_key=" + base64.b64encode(server_key),
            b"iterations=" + str(iterations).encode("ascii")
        ]
        return b",".join(parts)

    @classmethod
    def from_string(cls, raw: str) -> SCRAMCredentials:
        """Read the base64-encoded Kafka-style format.

        The user, algorithm, and ID fields are left unset.
        """
        parts = raw.split(",")
        keyval = dict(p.split("=", 1) for p in parts)
        return SCRAMCredentials(
            salt=base64.b64decode(keyval['salt']),
            stored_key=base64.b64decode(keyval['stored_key']),
            server_key=base64.b64decode(keyval['server_key']),
            iterations=int(keyval['iterations']),
            string_encoding=raw,
        )

    @staticmethod
    def b64string(val: bytes) -> str:
        return base64.b64encode(val).decode("ascii")
