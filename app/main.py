"""
SecureNotes API  —  Week 13 Security Lab (FIXED VERSION)
Web Systems and Technologies

A tiny notes service: users register, log in, and keep private notes.
Every fix below is tagged with the OWASP Top 10 (2025) code it addresses,
e.g. "# FIX A05", so reviewers can find it quickly in the PR diff.

Run it:
    uvicorn app.main:app --reload
Open the interactive docs at:
    http://127.0.0.1:8000/docs

Optional environment variables:
    SECRET_KEY       key used to sign tokens (random per-run if not set)
    ALLOWED_ORIGINS  comma-separated list of origins allowed by CORS
"""

import base64
import hashlib
import hmac
import logging
import os
import secrets
import sqlite3
import time

from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

logger = logging.getLogger("securenotes")

# --- app + config ----------------------------------------------------------
app = FastAPI(title="SecureNotes API", version="1.0")

# FIX A02 (Security Misconfiguration): the signing secret is no longer
# hardcoded in the source. It comes from an environment variable; if none is
# set we generate a random one for this run (tokens then reset on restart).
SECRET_KEY = os.environ.get("SECRET_KEY")
if not SECRET_KEY:
    SECRET_KEY = secrets.token_hex(32)
    logger.warning("SECRET_KEY not set - using a random key for this run only.")
SECRET_BYTES = SECRET_KEY.encode()

TOKEN_TTL_SECONDS = 15 * 60  # FIX A07: tokens expire after 15 minutes

# FIX A02: CORS locked to real, explicit origins instead of "*" + credentials.
ALLOWED_ORIGINS = [
    o.strip()
    for o in os.environ.get(
        "ALLOWED_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000"
    ).split(",")
    if o.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)


# --- password hashing (FIX A04) --------------------------------------------
PBKDF2_ITERATIONS = 600_000


def hash_password(password: str) -> str:
    """Salted PBKDF2-HMAC-SHA256. Stored as 'algo$iterations$salt$hash'."""
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt, PBKDF2_ITERATIONS
    )
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    """Re-hash with the stored salt and compare in constant time."""
    try:
        _algo, iterations, salt_hex, hash_hex = stored.split("$")
        digest = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), bytes.fromhex(salt_hex), int(iterations)
        )
        return hmac.compare_digest(digest, bytes.fromhex(hash_hex))
    except (ValueError, TypeError):
        return False  # a malformed stored hash never matches


# Used so "unknown user" takes as long as "wrong password" (no timing leak).
DUMMY_HASH = hash_password("not-a-real-password")


# --- signed, expiring tokens (FIX A07) -------------------------------------
def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def make_token(user_id: int) -> str:
    """token = base64(user_id:expiry) . base64(HMAC-SHA256 signature)"""
    payload = f"{user_id}:{int(time.time()) + TOKEN_TTL_SECONDS}".encode()
    signature = hmac.new(SECRET_BYTES, payload, hashlib.sha256).digest()
    return f"{_b64(payload)}.{_b64(signature)}"


def read_token(token: str):
    """Return the user id if the token is genuine and unexpired, else None."""
    try:
        payload_b64, signature_b64 = token.split(".")
        payload = _unb64(payload_b64)
        expected = hmac.new(SECRET_BYTES, payload, hashlib.sha256).digest()
        if not hmac.compare_digest(_unb64(signature_b64), expected):
            return None  # forged or tampered
        user_id, expires_at = payload.decode().split(":")
        if time.time() > int(expires_at):
            return None  # expired
        return int(user_id)
    except (ValueError, TypeError):
        return None  # anything odd -> reject (fail closed)


# --- database (SQLite, created fresh on startup) ---------------------------
db = sqlite3.connect(":memory:", check_same_thread=False)
db.row_factory = sqlite3.Row


def init_db():
    db.executescript(
        """
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            is_admin INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            body TEXT NOT NULL
        );
        """
    )
    # seed: one admin, two normal users, a few notes
    # FIX A04: seeded passwords are stored hashed, never as plain text.
    seed_users = [("admin", "admin123", 1), ("alice", "alicepass", 0), ("bob", "bobpass", 0)]
    for username, password, is_admin in seed_users:
        db.execute(
            "INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)",
            (username, hash_password(password), is_admin),
        )
    db.execute("INSERT INTO notes (owner_id, title, body) VALUES (2,'Alice diary','Alice secret note')")
    db.execute("INSERT INTO notes (owner_id, title, body) VALUES (3,'Bob plans','Bob secret note')")
    db.commit()


init_db()


# --- request models --------------------------------------------------------
class Credentials(BaseModel):
    username: str
    password: str


class NewNote(BaseModel):
    title: str
    body: str


# --- auth helper -----------------------------------------------------------
def current_user(authorization: str = Header(default=None)):
    """Validate the signed token and return the user row, or raise 401."""
    scheme, _, token = (authorization or "").partition(" ")
    user_id = read_token(token) if scheme.lower() == "bearer" and token else None
    row = (
        db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if user_id is not None
        else None
    )
    if row is None:
        # FIX A10: a missing/bad user is now a clean 401 instead of a crash
        # (previously user["id"] on None -> TypeError -> 500 + stack trace).
        raise HTTPException(
            status_code=401,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return row


# --- error handling --------------------------------------------------------
@app.exception_handler(Exception)
async def handle_everything(request, exc):
    # FIX A02: details go to the server log only; the client gets a generic
    # message with no exception text and no stack trace.
    logger.error(
        "Unhandled error on %s %s", request.method, request.url.path, exc_info=exc
    )
    return JSONResponse(status_code=500, content={"error": "Internal server error"})


# --- routes ----------------------------------------------------------------
@app.post("/register")
def register(creds: Credentials):
    try:
        db.execute(
            "INSERT INTO users (username, password, is_admin) VALUES (?, ?, 0)",
            (creds.username, hash_password(creds.password)),  # FIX A04
        )
        db.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail="Username already taken")
    return {"message": f"user {creds.username} created"}


@app.post("/login")
def login(creds: Credentials):
    # FIX A05: parameterized query - input is data, never SQL code.
    row = db.execute(
        "SELECT id, password FROM users WHERE username = ?", (creds.username,)
    ).fetchone()

    # FIX A07: same work + same message whether the user exists or not.
    stored = row["password"] if row is not None else DUMMY_HASH
    password_ok = verify_password(creds.password, stored)
    if row is None or not password_ok:
        raise HTTPException(status_code=401, detail="Invalid username or password")

    return {"token": make_token(row["id"]), "expires_in": TOKEN_TTL_SECONDS}


@app.get("/notes")
def list_my_notes(authorization: str = Header(default=None)):
    user = current_user(authorization)
    rows = db.execute("SELECT * FROM notes WHERE owner_id = ?", (user["id"],)).fetchall()
    return [dict(r) for r in rows]


@app.get("/notes/{note_id}")
def get_note(note_id: int, authorization: str = Header(default=None)):
    user = current_user(authorization)
    # FIX A01: only return the note if it belongs to the caller. Someone
    # else's note gets the same 404 as a missing one (don't reveal it exists).
    row = db.execute(
        "SELECT * FROM notes WHERE id = ? AND owner_id = ?", (note_id, user["id"])
    ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Note not found")
    return dict(row)


@app.post("/notes")
def create_note(note: NewNote, authorization: str = Header(default=None)):
    user = current_user(authorization)
    cur = db.execute(
        "INSERT INTO notes (owner_id, title, body) VALUES (?, ?, ?)",
        (user["id"], note.title, note.body),
    )
    db.commit()
    return {"id": cur.lastrowid, "title": note.title}


@app.get("/admin/users")
def list_all_users(authorization: str = Header(default=None)):
    user = current_user(authorization)
    # FIX A10: the permission check is no longer wrapped in try/except-pass.
    # If anything is wrong, the request is denied (fail closed).
    if not user["is_admin"]:
        raise HTTPException(status_code=403, detail="Admins only")
    # FIX A04: never send password hashes to the client - pick safe columns.
    rows = db.execute("SELECT id, username, is_admin FROM users").fetchall()
    return [dict(r) for r in rows]


@app.get("/")
def home():
    return {"service": "SecureNotes API", "docs": "/docs"}
