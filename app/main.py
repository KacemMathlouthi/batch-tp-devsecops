import hashlib
import hmac
import html
import ipaddress
import os
import secrets
import shutil
import socket
import sqlite3
# subprocess is only ever called with an argv list, never with shell=True
import subprocess  # nosec B404
from contextlib import asynccontextmanager
from pathlib import Path

import yaml
from fastapi import FastAPI, Form, HTTPException
from fastapi.responses import HTMLResponse
from jinja2 import Environment, FileSystemLoader, select_autoescape

APP_VERSION = os.getenv("APP_VERSION", "dev")
POD_NAME = os.getenv("POD_NAME", socket.gethostname())
DB_PATH = os.getenv("DB_PATH", str(Path(__file__).parent / "data" / "notes.db"))

# Secrets come from the environment, never from the code
SECRET_KEY = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD")
PING_BIN = shutil.which("ping")  # absolute path, resolved once

templates = Environment(
    loader=FileSystemLoader(Path(__file__).parent / "templates"),
    autoescape=select_autoescape(["html"]),
)


def db() -> sqlite3.Connection:
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600_000)
    return f"{salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    salt, _, _ = stored.partition("$")
    return hmac.compare_digest(hash_password(password, bytes.fromhex(salt)), stored)


def init_db() -> None:
    with db() as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT)")
        conn.execute("CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY, owner TEXT, title TEXT, body TEXT)")
        if ADMIN_PASSWORD:
            conn.execute(
                "INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)", ("admin", hash_password(ADMIN_PASSWORD))
            )
        conn.execute("INSERT OR IGNORE INTO notes (id, owner, title, body) VALUES (1, 'admin', 'Bienvenue', 'Premiere note')")
        conn.execute("INSERT OR IGNORE INTO notes (id, owner, title, body) VALUES (2, 'admin', 'Prive', 'Code coffre: 4242')")


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    yield


app = FastAPI(title="tp-devsecops", lifespan=lifespan)


@app.get("/", response_class=HTMLResponse)
def index():
    with db() as conn:
        notes = conn.execute("SELECT id, owner, title FROM notes").fetchall()
    return templates.get_template("index.html").render(version=APP_VERSION, pod=POD_NAME, notes=notes)


@app.get("/search")
def search(q: str = ""):
    with db() as conn:
        rows = conn.execute("SELECT id, owner, title, body FROM notes WHERE title LIKE ?", (f"%{q}%",)).fetchall()
    return [dict(r) for r in rows]


@app.get("/hello", response_class=HTMLResponse)
def hello(name: str = "visiteur"):
    return f"<h1>Bonjour {html.escape(name)}</h1>"


@app.post("/login")
def login(username: str = Form(...), password: str = Form(...)):
    with db() as conn:
        user = conn.execute("SELECT username, password FROM users WHERE username = ?", (username,)).fetchone()
    if user is None or not verify_password(password, user["password"]):
        return {"ok": False}
    token = hmac.new(SECRET_KEY.encode(), username.encode(), hashlib.sha256).hexdigest()
    return {"ok": True, "token": token}


@app.get("/ping")
def ping(host: str = "127.0.0.1"):
    try:
        ip = str(ipaddress.ip_address(host))
    except ValueError:
        raise HTTPException(status_code=400, detail="host must be an IP address")
    if PING_BIN is None:
        raise HTTPException(status_code=503, detail="ping is not available")
    out = subprocess.run([PING_BIN, "-c", "1", ip], capture_output=True, text=True, timeout=5, check=False)  # nosec B603
    return {"host": ip, "output": out.stdout}


@app.post("/import")
def import_notes(payload: str = Form(...)):
    try:
        data = yaml.safe_load(payload)
    except yaml.YAMLError:
        raise HTTPException(status_code=400, detail="invalid YAML")
    if not isinstance(data, dict):
        raise HTTPException(status_code=400, detail="expected a mapping")
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
