# Authentication

Vigolium uses a file-based user system with Bearer token authentication. Each user has a unique access code that serves as their API token.

## Users and Roles

Users are defined in a JSON file (default: `~/.vigolium/users.json`). On first run, the file is auto-created from the embedded template with randomly generated access codes (prefixed `vgl_`).

Three roles control API access:

| Role | Description |
|------|-------------|
| `admin` | Full access — can delete resources, update config, manage projects |
| `operator` | Can run scans, ingest traffic, and execute agent operations |
| `viewer` | Read-only access to records, findings, stats, and scan history |

Default users created on bootstrap:

| Name | Role |
|------|------|
| `vigolium-admin` | admin |
| `vigolium-operator` | operator |
| `vigolium-analyst` | viewer |
| `vigolium-auditor` | viewer |

## Login

Exchange a username and access code for user info and a Bearer token.

### `POST /api/auth/login`

This endpoint is publicly accessible (no authentication required).

**Request body:**

```json
{
  "username": "vigolium-admin",
  "access_code": "vgl_abc123..."
}
```

**Success response (200):**

```json
{
  "token": "vgl_abc123...",
  "user": {
    "uuid": "d4f5e6a7-...",
    "name": "vigolium-admin",
    "email": "",
    "role": "admin"
  }
}
```

**Error responses:**

| Status | Condition | Body |
|--------|-----------|------|
| 400 | Missing or malformed request body | `{"error": "username and access_code are required", "code": 400}` |
| 401 | Invalid username or access code | `{"error": "invalid username or access code", "code": 401}` |

## Current User Info

Retrieve the authenticated user's identity and role.

### `GET /api/user/info`

Requires a valid Bearer token.

**Success response (200):**

```json
{
  "uuid": "d4f5e6a7-...",
  "name": "vigolium-admin",
  "email": "",
  "role": "admin"
}
```

**Error responses:**

| Status | Condition | Body |
|--------|-----------|------|
| 401 | Missing or invalid token | `{"error": "invalid Bearer token", "code": 401}` |

## Using the Token

Include the token as a Bearer token in the `Authorization` header for all subsequent API requests:

```bash
curl -H "Authorization: Bearer vgl_abc123..." http://localhost:9002/api/info
```

## Disabling Authentication

Pass `-A` / `--no-auth` to `vigolium server` to disable authentication for
that process. There is no persistent `server.no_auth` config key. This mode is
not recommended for production use.
