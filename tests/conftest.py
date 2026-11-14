import base64
import os
import uuid

import pytest

from app.config import load_dotenv

load_dotenv()
if not os.environ.get("AES_KEY_B64"):
    os.environ["AES_KEY_B64"] = base64.b64encode(os.urandom(32)).decode()
if not os.environ.get("CAPABILITY_SECRET"):
    os.environ["CAPABILITY_SECRET"] = uuid.uuid4().hex + uuid.uuid4().hex
os.environ.setdefault("DB_PASSWORD", "ChangeMe12345Only")
os.environ["FLASK_ENV"] = "development"


@pytest.fixture()
def client():
    from app import create_app
    return create_app().test_client()


def new_user(client, password="Passw0rd123"):
    name = "u" + uuid.uuid4().hex[:10]
    r = client.post("/api/register", json={"username": name, "email": name + "@mail.com", "password": password})
    assert r.status_code == 201, r.get_json()
    return name, password


def get_token(client, username, password, scope):
    session = client.post("/api/login", json={"username": username, "password": password}).get_json()["session"]
    r = client.post("/api/capability", json={"scope": scope}, headers={"X-Capability": session})
    assert r.status_code == 200, r.get_json()
    return r.get_json()["token"]