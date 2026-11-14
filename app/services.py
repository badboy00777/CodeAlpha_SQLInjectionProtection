import pymysql

from app.capability import CapabilityError, issue_token, verify_token
from app.config import get_settings
from app.crypto import CryptoError, decrypt, encrypt
from app.db import get_connection
from app.passwords import hash_password, verify_password
from app.queries import get_query
from app.validators import (ValidationError, validate_email, validate_note,
                            validate_password, validate_username)

MAX_FAILED_LOGINS = 5
SESSION_TTL = 900
USER_SCOPES = {"profile:read", "notes:read", "notes:write"}


class ServiceError(Exception):
    def __init__(self, message, status):
        super().__init__(message)
        self.message = message
        self.status = status


def _cfg():
    s = get_settings()
    if len(s["AES_KEY"]) != 32 or not s["CAPABILITY_SECRET"]:
        raise ServiceError("Server is not configured", 500)
    return s


def _clean(fn, value):
    try:
        return fn(value)
    except ValidationError as exc:
        raise ServiceError(str(exc), 400)


def _check_token(token, scope):
    if not token:
        raise ServiceError("Capability token required", 401)
    try:
        return verify_token(_cfg()["CAPABILITY_SECRET"], token, scope)
    except CapabilityError as exc:
        raise ServiceError("Capability token rejected: " + str(exc), 403)


def register_user(data):
    s = _cfg()
    data = data if isinstance(data, dict) else {}
    username = _clean(validate_username, data.get("username"))
    email = _clean(validate_email, data.get("email"))
    password = _clean(validate_password, data.get("password"))
    email_enc = encrypt(email, s["AES_KEY"], aad=username.encode())
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(get_query("user_insert"), (username, email_enc, hash_password(password)))
        conn.commit()
    except pymysql.err.IntegrityError:
        conn.rollback()
        raise ServiceError("Username already taken", 409)
    finally:
        conn.close()
    return {"message": "registered"}


def login_user(data, ip):
    s = _cfg()
    data = data if isinstance(data, dict) else {}
    username = _clean(validate_username, data.get("username"))
    password = data.get("password")
    if not isinstance(password, str) or not password:
        raise ServiceError("Password required", 400)
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(get_query("attempts_count"), (username, ip))
            if cur.fetchone()["n"] >= MAX_FAILED_LOGINS:
                raise ServiceError("Too many failed logins. Try again in 10 minutes", 429)
            cur.execute(get_query("user_by_name"), (username,))
            user = cur.fetchone()
            if not user or not verify_password(password, user["password_hash"]):
                cur.execute(get_query("attempt_insert"), (username, ip))
                conn.commit()
                raise ServiceError("Wrong username or password", 401)
        return {"session": issue_token(s["CAPABILITY_SECRET"], user["id"], "session", ttl=SESSION_TTL)}
    finally:
        conn.close()


def issue_scope_token(session_token, scope):
    s = _cfg()
    payload = _check_token(session_token, "session")
    if scope not in USER_SCOPES:
        raise ServiceError("Unknown scope", 400)
    return {"token": issue_token(s["CAPABILITY_SECRET"], payload["uid"], scope, ttl=s["CAPABILITY_TTL"]),
            "scope": scope, "expires_in": s["CAPABILITY_TTL"]}


def get_profile(token):
    s = _cfg()
    payload = _check_token(token, "profile:read")
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(get_query("profile:read"), (payload["uid"],))
            row = cur.fetchone()
    finally:
        conn.close()
    if not row:
        raise ServiceError("User not found", 404)
    try:
        email = decrypt(row["email_enc"], s["AES_KEY"], aad=row["username"].encode())
    except CryptoError:
        raise ServiceError("Stored data failed integrity check", 500)
    return {"username": row["username"], "email": email}


def list_notes(token):
    s = _cfg()
    payload = _check_token(token, "notes:read")
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(get_query("notes:read"), (payload["uid"],))
            rows = cur.fetchall()
    finally:
        conn.close()
    aad = ("note:%d" % payload["uid"]).encode()
    notes = []
    for r in rows:
        try:
            text = decrypt(r["content_enc"], s["AES_KEY"], aad=aad)
        except CryptoError:
            text = "[corrupted]"
        notes.append({"id": r["id"], "text": text, "created_at": str(r["created_at"])})
    return {"notes": notes}


def add_note(token, data):
    s = _cfg()
    payload = _check_token(token, "notes:write")
    data = data if isinstance(data, dict) else {}
    text = _clean(validate_note, data.get("text"))
    content_enc = encrypt(text, s["AES_KEY"], aad=("note:%d" % payload["uid"]).encode())
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            try:   # one-time token: a replayed token hits the PRIMARY KEY and is refused
                cur.execute(get_query("token_use"), (payload["jti"],))
            except pymysql.err.IntegrityError:
                conn.rollback()
                raise ServiceError("Capability token already used", 403)
            cur.execute(get_query("notes:write"), (payload["uid"], content_enc))
        conn.commit()
    finally:
        conn.close()
    return {"message": "note saved"}


def db_is_up():
    try:
        get_connection().close()
        return True
    except Exception:
        return False