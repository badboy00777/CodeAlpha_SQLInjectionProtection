"""AES-256-GCM encryption for sensitive fields."""
import base64
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE_SIZE = 12


class CryptoError(Exception):
    pass


def _check_key(key):
    if not isinstance(key, (bytes, bytearray)) or len(key) != 32:
        raise CryptoError("AES key must be exactly 32 bytes (AES-256)")


def encrypt(plaintext, key, aad=b""):
    """Returns base64(nonce + ciphertext + tag). New random nonce every call."""
    _check_key(key)
    nonce = os.urandom(NONCE_SIZE)
    ct = AESGCM(bytes(key)).encrypt(nonce, plaintext.encode("utf-8"), aad)
    return base64.b64encode(nonce + ct).decode("ascii")


def decrypt(token, key, aad=b""):
    _check_key(key)
    try:
        raw = base64.b64decode(token.encode("ascii"), validate=True)
        nonce, ct = raw[:NONCE_SIZE], raw[NONCE_SIZE:]
        return AESGCM(bytes(key)).decrypt(nonce, ct, aad).decode("utf-8")
    except (InvalidTag, ValueError, UnicodeError) as exc:
        raise CryptoError("Decryption failed: data tampered or wrong key") from exc