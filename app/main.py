import hashlib
import os
import socket
import sqlite3
import subprocess
from pathlib import Path

import yaml
from fastapi import FastAPI, Form
from fastapi.responses import HTMLResponse
from jinja2 import Environment, FileSystemLoader

APP_VERSION = os.getenv("APP_VERSION", "dev")
POD_NAME = os.getenv("POD_NAME", socket.gethostname())
DB_PATH = os.getenv("DB_PATH", "/tmp/notes.db")

# Signing key and admin credentials for the API
SECRET_KEY = "s3cr3t-k3y-d0nt-sh4re-2026"
ADMIN_PASSWORD = "admin123"

app = FastAPI(title="tp-devsecops")
templates = Environment(loader=FileSystemLoader(Path(__file__).parent / "templates"))


def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def hash_password(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()


@app.on_event("startup")
def init_db() -> None:
    with db() as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT)")
        conn.execute("CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY, owner TEXT, title TEXT, body TEXT)")
        conn.execute("INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)", ("admin", hash_password(ADMIN_PASSWORD)))
        conn.execute("INSERT OR IGNORE INTO notes (id, owner, title, body) VALUES (1, 'admin', 'Bienvenue', 'Premiere note')")
        conn.execute("INSERT OR IGNORE INTO notes (id, owner, title, body) VALUES (2, 'admin', 'Prive', 'Code coffre: 4242')")


@app.get("/", response_class=HTMLResponse)
def index():
    with db() as conn:
        notes = conn.execute("SELECT id, owner, title FROM notes").fetchall()
    return templates.get_template("index.html").render(version=APP_VERSION, pod=POD_NAME, notes=notes)


@app.get("/search")
def search(q: str = ""):
    with db() as conn:
        rows = conn.execute(f"SELECT id, owner, title, body FROM notes WHERE title LIKE '%{q}%'").fetchall()
    return [dict(r) for r in rows]


@app.get("/hello", response_class=HTMLResponse)
def hello(name: str = "visiteur"):
    return f"<h1>Bonjour {name}</h1>"


@app.post("/login")
def login(username: str = Form(...), password: str = Form(...)):
    with db() as conn:
        user = conn.execute(
            "SELECT username FROM users WHERE username = ? AND password = ?", (username, hash_password(password))
        ).fetchone()
    if user is None:
        return {"ok": False}
    token = hashlib.md5(f"{username}:{SECRET_KEY}".encode()).hexdigest()
    return {"ok": True, "token": token}


@app.get("/ping")
def ping(host: str = "127.0.0.1"):
    out = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True, text=True, timeout=5)
    return {"host": host, "output": out.stdout}


@app.post("/import")
def import_notes(payload: str = Form(...)):
    data = yaml.load(payload, Loader=yaml.Loader)
    with db() as conn:
        for note in data.get("notes", []):
            conn.execute("INSERT INTO notes (owner, title, body) VALUES (?, ?, ?)", ("import", note["title"], note["body"]))
    return {"imported": len(data.get("notes", []))}


@app.get("/version")
def version():
    return {"version": APP_VERSION, "pod": POD_NAME}


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
