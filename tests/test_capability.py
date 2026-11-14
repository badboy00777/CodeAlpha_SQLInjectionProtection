import pytest
from app.capability import issue_token, verify_token, CapabilityError

S = "test-secret-long-random"


def test_valid_token():
    t = issue_token(S, 7, "notes:read", ttl=60, now=1000)
    p = verify_token(S, t, "notes:read", expected_user=7, now=1010)
    assert p["uid"] == 7 and len(p["jti"]) == 32


def test_expired():
    t = issue_token(S, 7, "notes:read", ttl=60, now=1000)
    with pytest.raises(CapabilityError):
        verify_token(S, t, "notes:read", now=1061)


def test_wrong_scope():
    t = issue_token(S, 7, "notes:read")
    with pytest.raises(CapabilityError):
        verify_token(S, t, "notes:write")


def test_wrong_user():
    t = issue_token(S, 7, "notes:read")
    with pytest.raises(CapabilityError):
        verify_token(S, t, "notes:read", expected_user=8)


def test_tampered_payload():
    t = issue_token(S, 7, "notes:read")
    sig = t.split(".")[1]
    forged = issue_token(S, 1, "notes:read").split(".")[0] + "." + sig
    with pytest.raises(CapabilityError):
        verify_token(S, forged, "notes:read")


def test_wrong_secret_and_garbage():
    t = issue_token(S, 7, "notes:read")
    with pytest.raises(CapabilityError):
        verify_token("other", t, "notes:read")
    for bad in ["", "abc", "a.b", "....", "x" * 50]:
        with pytest.raises(CapabilityError):
            verify_token(S, bad, "notes:read")


def test_unknown_scope_cannot_be_issued():
    with pytest.raises(CapabilityError):
        issue_token(S, 1, "admin:all")