import os
import pytest
from app.crypto import encrypt, decrypt, CryptoError
from app.passwords import hash_password, verify_password

KEY = os.urandom(32)


def test_roundtrip():
    assert decrypt(encrypt("secret@mail.com", KEY), KEY) == "secret@mail.com"


def test_random_nonce_gives_different_ciphertext():
    assert encrypt("same", KEY) != encrypt("same", KEY)


def test_tamper_detected():
    t = encrypt("hello", KEY)
    bad = t[:-4] + ("AAAA" if t[-4:] != "AAAA" else "BBBB")
    with pytest.raises(CryptoError):
        decrypt(bad, KEY)


def test_wrong_key_fails():
    with pytest.raises(CryptoError):
        decrypt(encrypt("x", KEY), os.urandom(32))


def test_key_must_be_256_bit():
    with pytest.raises(CryptoError):
        encrypt("x", os.urandom(16))


def test_password_hash_and_verify():
    h = hash_password("Passw0rd123")
    assert h != "Passw0rd123" and verify_password("Passw0rd123", h)
    assert not verify_password("wrong12345", h)
    assert hash_password("Passw0rd123") != h