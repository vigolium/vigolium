# Vigolium API Reference — GitHub Integration

Connect a GitHub account via OAuth to browse repositories and clone them as source code for agent scans.

## Setup

Register a GitHub OAuth App at https://github.com/settings/developers and configure in `vigolium-configs.yaml`:

```yaml
github:
  client_id: "Iv1.abc123..."
  client_secret: "secret..."
  callback_url: "http://localhost:9002/api/github/callback"
  scopes: "repo,read:user"    # optional, defaults to "repo,read:user"
```

---

## GET /api/github/auth-url — Get OAuth Authorize URL

Returns the GitHub OAuth authorization URL. The frontend opens this in a popup window.

**Role:** operator

```bash
curl -s http://localhost:9002/api/github/auth-url \
  -H "Authorization: Bearer TOKEN" | jq .
```

```json
{
  "url": "https://github.com/login/oauth/authorize?client_id=Iv1.abc123&redirect_uri=http%3A%2F%2Flocalhost%3A9002%2Fapi%2Fgithub%2Fcallback&scope=repo%2Cread%3Auser&state=a1b2c3d4e5f6"
}
```

---

## GET /api/github/callback — OAuth Callback (Browser Redirect)

GitHub redirects the browser here after the user authorizes. This endpoint exchanges the code for an access token, stores the connection, and serves a small HTML page that closes the popup window.

**Role:** public (no auth required — browser redirect from GitHub)

**Query parameters:**

| Parameter | Type   | Required | Description                           |
|-----------|--------|----------|---------------------------------------|
| `code`    | string | Yes      | Authorization code from GitHub        |
| `state`   | string | Yes      | CSRF state parameter (must match)     |

This endpoint is not called directly — it is the `redirect_uri` registered with the GitHub OAuth App.

---

## POST /api/github/callback — Exchange OAuth Code (JSON API)

Alternative JSON endpoint for exchanging an OAuth code. Used when the frontend handles the code extraction from the popup.

**Role:** operator

**Request body:**

| Field   | Type   | Required | Description                        |
|---------|--------|----------|------------------------------------|
| `code`  | string | Yes      | Authorization code from GitHub     |
| `state` | string | Yes      | CSRF state parameter               |

```bash
curl -s -X POST http://localhost:9002/api/github/callback \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"code": "abc123", "state": "a1b2c3d4e5f6"}' | jq .
```

```json
{
  "connected": true,
  "github_login": "octocat"
}
```

---

## GET /api/github/status — Connection Status

Returns whether the current user has a connected GitHub account for the active project.

**Role:** operator

```bash
curl -s http://localhost:9002/api/github/status \
  -H "Authorization: Bearer TOKEN" | jq .
```

**Connected:**
```json
{
  "configured": true,
  "connected": true,
  "github_login": "octocat",
  "connected_at": "2026-03-18T10:00:00Z"
}
```

**Not connected:**
```json
{
  "configured": true,
  "connected": false
}
```

**GitHub not configured on server:**
```json
{
  "configured": false,
  "connected": false
}
```

---

## DELETE /api/github/disconnect — Disconnect GitHub

Removes the stored GitHub access token for the current user and project.

**Role:** operator

```bash
curl -s -X DELETE http://localhost:9002/api/github/disconnect \
  -H "Authorization: Bearer TOKEN" | jq .
```

```json
{
  "disconnected": true
}
```

---

## GET /api/github/repos — List Repositories

Lists repositories accessible to the connected GitHub account. Proxied through the backend — the GitHub access token is never exposed to the frontend.

**Role:** operator

**Query parameters:**

| Parameter  | Type   | Default | Description                                       |
|------------|--------|---------|---------------------------------------------------|
| `page`     | int    | 1       | Page number                                       |
| `per_page` | int    | 30      | Results per page (max 100)                        |
| `q`        | string |         | Search query (uses GitHub search API when set)    |

```bash
# List repos (most recently updated first)
curl -s 'http://localhost:9002/api/github/repos?per_page=5' \
  -H "Authorization: Bearer TOKEN" | jq .

# Search repos
curl -s 'http://localhost:9002/api/github/repos?q=api-service' \
  -H "Authorization: Bearer TOKEN" | jq .
```

```json
[
  {
    "id": 123456,
    "full_name": "myorg/api-service",
    "name": "api-service",
    "owner": "myorg",
    "private": true,
    "default_branch": "main",
    "language": "Go",
    "description": "REST API backend",
    "html_url": "https://github.com/myorg/api-service",
    "clone_url": "https://github.com/myorg/api-service.git",
    "updated_at": "2026-03-18T09:30:00Z"
  },
  {
    "id": 789012,
    "full_name": "myorg/web-frontend",
    "name": "web-frontend",
    "owner": "myorg",
    "private": false,
    "default_branch": "develop",
    "language": "TypeScript",
    "description": "React dashboard",
    "html_url": "https://github.com/myorg/web-frontend",
    "clone_url": "https://github.com/myorg/web-frontend.git",
    "updated_at": "2026-03-17T15:00:00Z"
  }
]
```

---

## GET /api/github/repos/:owner/:repo/branches — List Branches

Lists branches for a specific repository.

**Role:** operator

**Path parameters:**

| Parameter | Type   | Description          |
|-----------|--------|----------------------|
| `owner`   | string | Repository owner     |
| `repo`    | string | Repository name      |

```bash
curl -s http://localhost:9002/api/github/repos/myorg/api-service/branches \
  -H "Authorization: Bearer TOKEN" | jq .
```

```json
[
  { "name": "main" },
  { "name": "develop" },
  { "name": "feature/auth-v2" }
]
```

---

## POST /api/github/repos/clone — Clone Repository

Clones a GitHub repository to local storage. The GitHub access token is injected into the clone URL for private repo access. Uses shallow clone with configurable depth from `source_aware.clone_depth`.

**Role:** operator

**Request body:**

| Field       | Type   | Required | Description                                              |
|-------------|--------|----------|----------------------------------------------------------|
| `clone_url` | string | Yes      | HTTPS clone URL from the repo listing                    |
| `branch`    | string | No       | Branch to clone (defaults to repo's default branch)      |
| `hostname`  | string | No       | If set, creates a source_repo record linking hostname    |

```bash
curl -s -X POST http://localhost:9002/api/github/repos/clone \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "clone_url": "https://github.com/myorg/api-service.git",
    "branch": "main",
    "hostname": "api.example.com"
  }' | jq .
```

```json
{
  "path": "/home/user/.vigolium/source-repos/github.com_myorg_api-service",
  "source_repo_id": 42
}
```

**Without hostname (clone only, no source_repo record):**

```bash
curl -s -X POST http://localhost:9002/api/github/repos/clone \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "clone_url": "https://github.com/myorg/api-service.git"
  }' | jq .
```

```json
{
  "path": "/home/user/.vigolium/source-repos/github.com_myorg_api-service"
}
```

The returned `path` can be used as the `source` field in agent scan requests (swarm, pipeline, autopilot).

---

## Error Responses

All endpoints return standard error JSON on failure:

```json
{
  "error": "GitHub not connected. Connect your account first"
}
```

| Status | Meaning                                                      |
|--------|--------------------------------------------------------------|
| 400    | Missing or invalid parameters, expired state                 |
| 401    | GitHub not connected (no stored token for user/project)      |
| 502    | GitHub API error (token exchange failed, API unreachable)    |
| 503    | GitHub integration not configured on the server              |

---

## Typical OAuth Flow

1. Frontend calls `GET /api/github/auth-url` to get the authorize URL
2. Frontend opens the URL in a popup window
3. User authorizes the app on GitHub
4. GitHub redirects the popup to `GET /api/github/callback?code=X&state=Y`
5. Backend exchanges the code for an access token, stores it, and serves HTML that closes the popup
6. Frontend detects the popup closed and refetches `GET /api/github/status`
7. User can now browse repos via `GET /api/github/repos` and clone via `POST /api/github/repos/clone`

---

## Database

GitHub connections are stored in the `github_connections` table, scoped by `user_uuid` + `project_uuid` (one connection per user per project). Access tokens are stored in the database and never exposed via the API (`json:"-"` tag).
