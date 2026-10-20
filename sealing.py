"""The server's P-256 key pair, and opening secrets sealed by docs/seal.js.

The browser does ECDH between a one-off key pair and this server's public key,
derives an AES-256-GCM key with HKDF-SHA256 (salted with the request id), and
binds the ciphertext to the request with associated data. Only the private key
here can open it, so the tunnel in between only ever carries ciphertext.
"""
from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

INFO = b"secret-drop v1"


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def unb64u(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def aad(request_id: str, name: str) -> bytes:
    """Ties a ciphertext to one request, so it can't be replayed into another."""
    return b"%s\n%s\n%s" % (INFO, request_id.encode(), name.encode())


class KeyPair:
    def __init__(self, private_key: ec.EllipticCurvePrivateKey):
        self._key = private_key
        raw = private_key.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        self.public_b64u = b64u(raw)
        self.kid = hashlib.sha256(raw).hexdigest()[:16]

    @classmethod
    def load(cls, path: Path) -> "KeyPair":
        return cls(serialization.load_pem_private_key(path.read_bytes(), password=None))

    @classmethod
    def create(cls, path: Path) -> "KeyPair":
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        key = ec.generate_private_key(ec.SECP256R1())
        pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(pem)
        return cls(key)

    def public_json(self) -> dict:
        """What docs/pubkey.json publishes for the page."""
        return {"v": 1, "kid": self.kid, "key": self.public_b64u}

    def open(self, payload: dict, request_id: str, name: str) -> str:
        """Decrypt a docs/seal.js payload. Raises ValueError unless it was sealed for this request."""
        try:
            if payload.get("v") != 1:
                raise ValueError("unknown version")
            epk = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), unb64u(payload["epk"]))
            shared = self._key.exchange(ec.ECDH(), epk)
            key = HKDF(algorithm=hashes.SHA256(), length=32, salt=request_id.encode(),
                       info=INFO).derive(shared)
            plain = AESGCM(key).decrypt(unb64u(payload["iv"]), unb64u(payload["ct"]),
                                        aad(request_id, name))
            return plain.decode("utf-8")
        except Exception as e:  # malformed field, wrong key, tampered, or meant for another request
            raise ValueError("could not decrypt") from e
