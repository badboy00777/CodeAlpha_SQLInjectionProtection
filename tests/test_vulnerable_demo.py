import pytest
from tests.conftest import new_user

OR_PAYLOAD = "' OR '1'='1"
UNION_PAYLOAD = "x' UNION SELECT id, password_hash, email_enc FROM users -- "


@pytest.fixture()
def vclient(monkeypatch):
    monkeypatch.setenv("ALLOW_VULNERABLE_DEMO", "1")
    from app import create_app
    return create_app().test_client()


def test_demo_is_off_by_default(client, monkeypatch):
    monkeypatch.delenv("ALLOW_VULNERABLE_DEMO", raising=False)
    from app import create_app
    assert create_app().test_client().get("/vulnerable/search?name=a").status_code == 404


def test_attack_succeeds_on_vulnerable_search(vclient):
    new_user(vclient)
    new_user(vclient)
    rows = vclient.get("/vulnerable/search", query_string={"name": OR_PAYLOAD}).get_json()["rows"]
    assert len(rows) >= 2                      # dumped every user
    assert all("@" not in r["email_enc"] for r in rows)   # ...but emails are only ciphertext


def test_union_attack_leaks_hashes_not_passwords(vclient):
    new_user(vclient)
    rows = vclient.get("/vulnerable/search", query_string={"name": UNION_PAYLOAD}).get_json()["rows"]
    assert any(str(r["username"]).startswith("$2") for r in rows)   # bcrypt hash leaked, not the password


def test_login_bypass_on_vulnerable_login(vclient):
    name, _ = new_user(vclient)
    r = vclient.post("/vulnerable/login", json={"username": name + "' -- ", "password": "anything"})
    assert r.get_json()["logged_in"] is True


def test_same_attacks_fail_on_secure_endpoints(vclient):
    name, _ = new_user(vclient)
    assert vclient.post("/api/login", json={"username": name + "' -- ", "password": "anything"}).status_code == 400
    assert vclient.post("/api/login", json={"username": OR_PAYLOAD, "password": OR_PAYLOAD}).status_code == 400


def test_stacked_drop_fails_even_on_vulnerable_endpoint(vclient):
    r = vclient.get("/vulnerable/search", query_string={"name": "x'; DROP TABLE users; -- "})
    assert r.status_code == 500                # PyMySQL refuses stacked queries
    assert vclient.get("/vulnerable/search", query_string={"name": OR_PAYLOAD}).status_code == 200