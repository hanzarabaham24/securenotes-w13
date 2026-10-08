# Vulnerability Findings — Hanz & Rafael

There are **6** security bugs planted in `app/main.py`. Fill one row per bug.

(Line numbers refer to the ORIGINAL starter `app/main.py` on the `main` branch.)

| # | OWASP 2025 code & name | Where (route / line) | How an attacker abuses it | Your fix (1 line) |
|---|------------------------|----------------------|---------------------------|-------------------|
| 1 | **A05 – Injection** | `POST /login`, line 116: `f"SELECT ... WHERE username = '{creds.username}'"` | Username is pasted straight into the SQL. Sending `' UNION SELECT 1,'x'--` with password `x` makes the DB return a fake admin row (id 1, password `x`), so the attacker logs in as admin without knowing any password. A lone `'` also crashes the query. | Parameterized query: `WHERE username = ?` with `(creds.username,)`. |
| 2 | **A04 – Cryptographic Failures** | Passwords stored/compared/returned in plain text: seed users (lines 63-65), `POST /register` (lines 105-108), `POST /login` compare (line 120), and `GET /admin/users` returns `SELECT *` (line 160) | Anyone who reads the DB, a backup, or the `/admin/users` response sees every password, and people reuse passwords on other sites. The `!=` compare is also not constant-time. | Salted PBKDF2-HMAC-SHA256 (600k iterations) in `hash_password()`; check with `hmac.compare_digest`; `/admin/users` selects only `id, username, is_admin`. |
| 3 | **A01 – Broken Access Control** | `GET /notes/{note_id}`, lines 135-138 (looks up the note by id only; `user` is fetched but never used) | Log in as Alice, request `/notes/2` and read Bob's private note (IDOR). Changing the number walks through every user's notes. | Query `WHERE id = ? AND owner_id = ?`; other people's notes return the same 404 as missing ones. |
| 4 | **A07 – Authentication Failures** | `POST /login` lines 118-122 and `current_user()` lines 88-90: token is just the user id (`str(row["id"])`) and login returns different errors (404 "No account…" vs 401 "Wrong password") | Token `1` = admin, forever: an attacker just sends `Authorization: Bearer 1` (or 2, 3…) with no login at all, and it never expires. The two different errors let an attacker discover which usernames exist before guessing passwords. | Signed (HMAC-SHA256) token carrying user id + expiry (15 min), verified with `compare_digest`; one generic `401 Invalid username or password`; dummy hash for unknown users so timing matches. |
| 5 | **A02 – Security Misconfiguration** | Line 29 `SECRET_KEY = "supersecret123"` hardcoded; lines 31-37 CORS `allow_origins=["*"]` + `allow_credentials=True`; lines 94-99 exception handler returns `str(exc)` and `traceback.format_exc()` | The hardcoded secret is in the repo for anyone to read; any website can call the API from a victim's browser; error responses expose file paths, SQL and code structure that help craft attacks (e.g. the injection above). | Secret read from `SECRET_KEY` env var (random per run if absent); CORS limited to an explicit origin list + only needed methods/headers; handler logs the trace server-side and returns a generic `{"error": "Internal server error"}`. |
| 6 | **A10 – Mishandling of Exceptional Conditions (fails open)** | `GET /admin/users`, lines 155-159: `try: ... raise 403 ... except Exception: pass` | The 403 is raised inside a `try` whose `except` swallows it, so the code carries on and returns all users. Bob (non-admin) or someone with a garbage/no token (user is `None` → `TypeError`, also swallowed) gets the full user list. | Removed the try/except; `if not user["is_admin"]: raise 403` so any failure means deny. `current_user()` now raises a clean 401 instead of crashing. |

## Proof that the fixes work
`python test_attacks.py` re-runs every attack above:
- original starter: 9 attacks succeed (VULNERABLE)
- fixed code: all attacks BLOCKED, and register / login / create note / list my notes / open my own note / admin list still PASS (17/17 checks OK)

## Reflection (3–4 sentences)
Which bug would do the most damage in a real app, and why?

I think the SQL injection in the login was the most dangerous bug. Anyone could type a short piece of SQL into the username box and log in as the admin without knowing any password, and with a bigger payload they could read or delete the whole database. Most of the other bugs need something extra, like a valid account or a guessed token, but this one only needs the login form. It was also the easiest to cause by accident, because the whole problem was one f-string in the query.
