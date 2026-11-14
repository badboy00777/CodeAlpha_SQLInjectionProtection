import base64
import hashlib
import hmac
import json
import time
import uuid

SCOPES = {"profile:read", "notes:read", "notes:write", "session"}


class CapabilityError(Exception):
    pass


def _b64e(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _b64d(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _sign(secret, payload_b64):
    return hmac.new(secret.encode("utf-8"), payload_b64.encode("ascii"), hashlib.sha256).digest()


def issue_token(secret, user_id, scope, ttl=300, now=None):
    if not secret:
        raise CapabilityError("Missing signing secret")
    if scope not in SCOPES:
        raise CapabilityError("Unknown scope")
    now = int(now if now is not None else time.time())
    payload = {"uid": int(user_id), "scope": scope, "exp": now + int(ttl), "jti": uuid.uuid4().hex}
    p = _b64e(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    return p + "." + _b64e(_sign(secret, p))


def verify_token(secret, token, expected_scope, expected_user=None, now=None):
    """Returns payload dict or raises CapabilityError."""
    try:
        p, sig = token.split(".")
        good = _sign(secret, p)
        if not hmac.compare_digest(good, _b64d(sig)):
            raise CapabilityError("Bad signature")
        payload = json.loads(_b64d(p))
    except CapabilityError:
        raise
    except Exception as exc:
        raise CapabilityError("Malformed token") from exc
    now = int(now if now is not None else time.time())
    if payload.get("exp", 0) < now:
        raise CapabilityError("Token expired")
    if payload.get("scope") != expected_scope:
        raise CapabilityError("Wrong scope")
    if expected_user is not None and payload.get("uid") != int(expected_user):
        raise CapabilityError("Token belongs to another user")
    return payload