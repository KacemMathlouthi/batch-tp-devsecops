import os

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("DB_PATH", str(tmp_path / "notes.db"))
    import importlib

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
    password = os.environ.get("ADMIN_PASSWORD", "admin123")
    assert client.post("/login", data={"username": "admin", "password": password}).json()["ok"] is True
    assert client.post("/login", data={"username": "admin", "password": "nope"}).json()["ok"] is False


def test_hello(client):
    assert "Bonjour Kacem" in client.get("/hello", params={"name": "Kacem"}).text
