import time
import pytest
import pymysql

from app.db import get_connection
from tests.conftest import new_user, get_token
from tests.test_validators import PAYLOADS


def test_register_duplicate_and_weak_password(client):
    name, _ = new_user(client)
    r = client.post("/api/register", json={"username": name, "email": name + "@mail.com", "password": "Passw0rd123"})
    assert r.status_code == 409
    r = client.post("/api/register", json={"username": "x" + name, "email": "a@b.com", "password": "weak"})
    assert r.status_code == 400


def test_data_is_encrypted_and_hashed_in_database(client):
    name, _ = new_user(client)
    conn = get_connection()
    with conn.cursor() as cur:
        cur.execute("SELECT email_enc, password_hash FROM users WHERE username = %s", (name,))
        row = cur.fetchone()
    conn.close()
    assert "@" not in row["email_enc"] and name not in row["email_enc"]
    assert row["password_hash"].startswith("$2")


def test_full_flow_profile_and_notes(client):
    name, pw = new_user(client)
    t = get_token(client, name, pw, "profile:read")
    r = client.get("/api/profile", headers={"X-Capability": t})
    assert r.status_code == 200 and r.get_json()["email"] == name + "@mail.com"
    w = get_token(client, name, pw, "notes:write")
    r = client.post("/api/notes", json={"text": "Buy milk, 2 litres"}, headers={"X-Capability": w})
    assert r.status_code == 201
    rd = get_token(client, name, pw, "notes:read")
    r = client.get("/api/notes", headers={"X-Capability": rd})
    assert [n["text"] for n in r.get_json()["notes"]] == ["Buy milk, 2 litres"]


def test_write_token_is_one_time_use(client):
    name, pw = new_user(client)
    w = get_token(client, name, pw, "notes:write")
    assert client.post("/api/notes", json={"text": "first"}, headers={"X-Capability": w}).status_code == 201
    r = client.post("/api/notes", json={"text": "replay"}, headers={"X-Capability": w})
    assert r.status_code == 403


def test_wrong_scope_missing_and_garbage_token(client):
    name, pw = new_user(client)
    t = get_token(client, name, pw, "profile:read")
    assert client.get("/api/notes", headers={"X-Capability": t}).status_code == 403
    assert client.get("/api/profile").status_code == 401
    assert client.get("/api/profile", headers={"X-Capability": "abc.def"}).status_code == 403


def test_session_token_cannot_read_data_and_scope_cannot_be_escalated(client):
    name, pw = new_user(client)
    session = client.post("/api/login", json={"username": name, "password": pw}).get_json()["session"]
    assert client.get("/api/profile", headers={"X-Capability": session}).status_code == 403
    r = client.post("/api/capability", json={"scope": "session"}, headers={"X-Capability": session})
    assert r.status_code == 400


def test_users_cannot_see_each_others_notes(client):
    a, pa = new_user(client)
    b, pb = new_user(client)
    wb = get_token(client, b, pb, "notes:write")
    client.post("/api/notes", json={"text": "secret of B"}, headers={"X-Capability": wb})
    ra = get_token(client, a, pa, "notes:read")
    assert client.get("/api/notes", headers={"X-Capability": ra}).get_json()["notes"] == []


def test_wrong_password_and_rate_limit(client):
    name, _ = new_user(client)
    for _ in range(5):
        assert client.post("/api/login", json={"username": name, "password": "Wrong12345"}).status_code == 401
    assert client.post("/api/login", json={"username": name, "password": "Wrong12345"}).status_code == 429


@pytest.mark.parametrize("payload", PAYLOADS)
def test_injection_payloads_blocked_on_every_input(client, payload):
    name, pw = new_user(client)
    start = time.time()
    r1 = client.post("/api/register", json={"username": payload, "email": "a@b.com", "password": pw})
    r2 = client.post("/api/login", json={"username": payload, "password": payload})
    w = get_token(client, name, pw, "notes:write")
    r3 = client.post("/api/notes", json={"text": payload}, headers={"X-Capability": w})
    assert r1.status_code == 400 and r2.status_code == 400 and r3.status_code == 400
    assert time.time() - start < 3   # time-based payloads (SLEEP) never run


def test_even_injection_in_password_field_is_harmless(client):
    name, _ = new_user(client)
    r = client.post("/api/login", json={"username": name, "password": "' OR '1'='1"})
    assert r.status_code == 401


def test_layer2_db_user_cannot_delete_update_or_drop():
    conn = get_connection()
    with conn.cursor() as cur:
        for sql in ("DELETE FROM users", "UPDATE users SET username = 'x'", "DROP TABLE users"):
            with pytest.raises(pymysql.MySQLError):
                cur.execute(sql)
    conn.close()


def test_stacked_queries_are_not_possible():
    conn = get_connection()
    with conn.cursor() as cur:
        with pytest.raises(pymysql.MySQLError):
            cur.execute("SELECT 1; SELECT 2")
    conn.close()