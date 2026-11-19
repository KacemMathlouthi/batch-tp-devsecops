import importlib

import pytest
from fastapi.testclient import TestClient

ADMIN_PASSWORD = "test-only-password"


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("DB_PATH", str(tmp_path / "notes.db"))
    monkeypatch.setenv("ADMIN_PASSWORD", ADMIN_PASSWORD)
    import main

    importlib.reload(main)
    with TestClient(main.app) as c:
        yield c


def test_healthz(client):
    assert client.get("/healthz").json() == {"status": "ok"}


def test_index_lists_notes(client):
    r = client.get("/")
    assert r.status_code == 200
    assert "Bienvenue" in r.text


def test_search_finds_note(client):
    titles = [n["title"] for n in client.get("/search", params={"q": "Bien"}).json()]
    assert titles == ["Bienvenue"]


def test_login_ok_and_ko(client):
    assert client.post("/login", data={"username": "admin", "password": ADMIN_PASSWORD}).json()["ok"] is True
    assert client.post("/login", data={"username": "admin", "password": "nope"}).json()["ok"] is False


def test_hello(client):
    assert "Bonjour Kacem" in client.get("/hello", params={"name": "Kacem"}).text


def test_notes_by_owner(client):
    assert "Bienvenue" in client.get("/notes/by-owner", params={"owner": "admin"}).text


# ── Regression tests for the TP1 fixes ──────────────────────


def test_search_sql_injection_is_inert(client):
    payload = "%' UNION SELECT id, username, password, 'leak' FROM users --"
    assert client.get("/search", params={"q": payload}).json() == []


def test_hello_escapes_html(client):
    body = client.get("/hello", params={"name": "<script>alert(1)</script>"}).text
    assert "<script>" not in body
    assert "&lt;script&gt;" in body


def test_ping_rejects_shell_metacharacters(client):
    assert client.get("/ping", params={"host": "127.0.0.1;id"}).status_code == 400


def test_import_refuses_python_objects(client):
    payload = '!!python/object/apply:os.system ["id"]'
    assert client.post("/import", data={"payload": payload}).status_code == 400


def test_passwords_are_salted():
    import main

    assert main.hash_password("x") != main.hash_password("x")
    assert main.verify_password("x", main.hash_password("x"))


def test_notes_by_owner_injection_is_inert(client):
    body = client.get("/notes/by-owner", params={"owner": "' OR '1'='1"}).text
    assert "Bienvenue" not in body


def test_notes_by_owner_escapes_html(client):
    body = client.get("/notes/by-owner", params={"owner": "<script>alert(1)</script>"}).text
    assert "<script>" not in body
