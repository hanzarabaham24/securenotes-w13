"""
Re-runs the six attacks from Part A against the app and the three
"app still works" checks from Part B.

    pip install httpx
    python test_attacks.py

Prints VULNERABLE / BLOCKED for each attack, PASS / FAIL for normal use.
Exit code is 0 only if every attack is blocked and the app still works.
"""
import sys

from fastapi.testclient import TestClient

from app.main import app

# raise_server_exceptions=False so a crash shows up as a 500 response (like a
# real client would see) instead of raising inside this script.
c = TestClient(app, raise_server_exceptions=False)
results = []


def record(name, owasp, bad, kind="attack"):
    if kind == "attack":
        label = "VULNERABLE" if bad else "BLOCKED"
    else:
        label = "FAIL" if bad else "PASS"
    results.append((owasp, name, label, bad))
    print(f"[{label:10}] {owasp:4} {name}")


def login(user, pw):
    return c.post("/login", json={"username": user, "password": pw})


def auth(token):
    return {"Authorization": f"Bearer {token}"}


alice = login("alice", "alicepass").json().get("token")
bob = login("bob", "bobpass").json().get("token")

# --- ATTACKS ---------------------------------------------------------------
# A05 SQL injection: a UNION row makes the DB "return" id 1 + password 'x'.
r = login("' UNION SELECT 1,'x'--", "x")
record("SQL injection logs in as admin via /login", "A05", r.status_code == 200)

# A01 Broken access control: Alice reads Bob's note (note 2).
r = c.get("/notes/2", headers=auth(alice))
record("Alice reads Bob's note 2", "A01", r.status_code == 200)

# A04 Cryptographic failures: passwords visible in plain text anywhere?
admin = login("admin", "admin123").json().get("token")
r = c.get("/admin/users", headers=auth(admin))
leaked = any(p in r.text for p in ("admin123", "alicepass", "bobpass"))
record("Plaintext passwords returned by /admin/users", "A04", leaked)

# A07 (a) guessable token: just use the bare user id as the token.
r = c.get("/admin/users", headers={"Authorization": "Bearer 1"})
record("Forged token 'Bearer 1' accepted as admin", "A07", r.status_code == 200)

# A07 (b) username enumeration: do the two failures look different?
r1 = login("nobody_here", "x")
r2 = login("alice", "wrongpass")
record("Login reveals which usernames exist", "A07",
       (r1.status_code, r1.json()) != (r2.status_code, r2.json()))

# A10 Fail open: a normal user (Bob) calls the admin route.
r = c.get("/admin/users", headers=auth(bob))
record("Non-admin Bob lists all users", "A10", r.status_code == 200)
r = c.get("/admin/users", headers={"Authorization": "Bearer garbage"})
record("Garbage token reaches admin route", "A10", r.status_code == 200)

# A02 Misconfiguration: stack trace leaked to the client?
r = login("'", "x")
record("Stack trace / error text leaked on bad input", "A02",
       "trace" in r.text.lower() or "Traceback" in r.text or "sqlite" in r.text.lower())
r = c.options("/login", headers={"Origin": "https://evil.example",
                                 "Access-Control-Request-Method": "POST"})
record("CORS allows any origin (evil.example)", "A02",
       r.headers.get("access-control-allow-origin") in ("*", "https://evil.example"))

# --- Extra checks for the fixed code (skipped on the original) -------------
import app.main as m  # noqa: E402

if hasattr(m, "make_token"):
    import time
    real = time.time
    t = m.make_token(2)
    m.time.time = lambda: real() + m.TOKEN_TTL_SECONDS + 5
    expired_ok = c.get("/notes", headers=auth(t)).status_code == 200
    m.time.time = real
    record("Expired token still accepted", "A07", expired_ok)
    tampered = t[:-2] + ("AA" if not t.endswith("AA") else "BB")
    record("Tampered token signature accepted", "A07",
           c.get("/notes", headers=auth(tampered)).status_code == 200)

# --- APP STILL WORKS -------------------------------------------------------
r = c.post("/register", json={"username": "carol", "password": "carolpass"})
record("Register a new user", "-", r.status_code != 200, kind="use")
r = login("carol", "carolpass")
tok = r.json().get("token") if r.status_code == 200 else None
record("Log in as the new user", "-", tok is None, kind="use")
r = c.post("/notes", json={"title": "hi", "body": "mine"}, headers=auth(tok))
record("Create a note", "-", r.status_code != 200, kind="use")
r = c.get("/notes", headers=auth(tok))
record("List my own notes", "-", r.status_code != 200 or len(r.json()) != 1, kind="use")
r = c.get("/notes/1", headers=auth(alice))
record("Alice opens her own note 1", "-", r.status_code != 200, kind="use")
r = c.get("/admin/users", headers=auth(admin))
record("Admin can still list users", "-", r.status_code != 200, kind="use")

bad = [x for x in results if x[3]]
print(f"\n{len(results) - len(bad)}/{len(results)} checks OK")
sys.exit(1 if bad else 0)
