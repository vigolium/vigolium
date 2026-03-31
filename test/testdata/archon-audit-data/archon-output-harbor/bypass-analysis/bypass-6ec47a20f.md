# Bypass Analysis: CVE-2024-22278 (Patch 6ec47a20f)

## Metadata

- **Advisory**: CVE-2024-22278
- **Patch Commit**: 6ec47a20f
- **First Patch Commit**: 89e1c4baa
- **File Modified**: `src/server/middleware/security/v2_token.go`
- **Cluster ID**: CVE-2024-22278-cluster (commits: 89e1c4baa, 3ac6ff9e6, a8c8c8413, 6ec47a20f)
- **Type**: known-cve

---

## Patch Summary

### Vulnerability

When a Harbor project is deleted and a new project is created with the same name, a bearer token that was legitimately issued for the old project remains cryptographically valid (the signing key has not changed). An attacker holding such a stale token could re-use it to authenticate against the new project and gain unauthorized access to its repositories.

### Fix Mechanism

The patch adds a `tokenIssuedAfterProjectCreation()` guard in `v2Token.Generate()` inside `src/server/middleware/security/v2_token.go`. After the JWT is verified, the function:

1. Reads the `ProjectName` from the `ArtifactInfo` context key (populated upstream by `artifactinfo.Middleware()`).
2. If a project name is present, calls `project_ctl.Ctl.GetByName()` to fetch the current project record.
3. Compares the token's `iat` (issued-at) claim, extended by a `JwtLeeway` of 60 seconds, against the project's `CreationTime`.
4. Returns `nil` (rejecting the request) when `iat + leeway < project.CreationTime`.

### Backport / Cluster Relationship

Commits 89e1c4baa (main), 3ac6ff9e6 (release-2.15.0), a8c8c8413 (release-2.14.0), and 6ec47a20f (release-2.13.0) carry **byte-for-byte identical diffs**. This is a standard cherry-pick backport series. The second patch (6ec47a20f) is not fixing a different code path; it applies the same fix to the oldest still-supported release branch.

---

## Bypass Verdict

**bypassable** (partial — two gaps identified)

---

## Evidence

### Gap 1: ArtifactInfo not populated for `/v2/` and `/v2/_catalog` paths

The fix relies entirely on `lib.GetArtifactInfo(ctx)` returning a non-empty `ProjectName`. `ArtifactInfo` is populated by `artifactinfo.Middleware()`, which only fires when the request URL matches one of five regex patterns:

| Pattern | URLs covered |
|---|---|
| `V2ManifestURLRe` | `/v2/<repo>/manifests/<ref>` |
| `V2TagListURLRe` | `/v2/<repo>/tags/list` |
| `V2BlobURLRe` | `/v2/<repo>/blobs/<digest>` |
| `V2BlobUploadURLRe` | `/v2/<repo>/blobs/uploads[/...]` |
| `V2ReferrersURLRe` | `/v2/<repo>/referrers/<ref>` |

The base auth endpoint `GET /v2/` and the catalog endpoint `GET /v2/_catalog` do **not** match any of those patterns. For those requests, `info.ProjectName` is always `""`, and `tokenIssuedAfterProjectCreation()` returns `true` immediately (line 85-87 of the patched file):

```go
if info.ProjectName == "" {
    return true
}
```

A stale bearer token (with `iat` predating the new project) is therefore accepted without any `iat`-vs-`CreationTime` check for these two endpoints. In practice:

- `GET /v2/` is a ping/login check that does not expose project data on its own.
- `GET /v2/_catalog` lists all repositories harbor-wide and is separately gated by `IsSysAdmin()` in `v2auth/auth.go`; gaining a security context via a stale token alone does not grant catalog access.

The risk is **low but non-zero**: an attacker who obtains a stale system-level or admin bearer token with no specific scope could still authenticate (`IsAuthenticated() == true`) through the `/v2/` login path and receive a fresh scoped token via `/service/token`, circumventing the staleness check entirely.

### Gap 2: Token refresh / new token issuance not blocked

The fix validates tokens **at consumption time** in the registry middleware. It does not block the token-issuance endpoint (`GET /service/token` handled by `src/core/service/token/token.go`). The token service (`generalCreator.Create`) accepts any currently-authenticated session and mints a new JWT with a fresh `iat`. The flow:

1. Attacker presents stale bearer token to `GET /v2/` (no `ArtifactInfo` → staleness check skipped → authenticated).
2. Registry returns `WWW-Authenticate: Bearer realm=".../service/token"` challenge with the desired scope.
3. Attacker calls `GET /service/token?service=harbor-registry&scope=repository:newproject/myrepo:pull`.
4. `repositoryFilter.filter()` in `creator.go` calls `project_ctl.Ctl.GetByName()` and checks the **current** user's RBAC permissions against the **new** project. If those permissions exist (e.g., the attacker's account is a member of the new project too), a fresh, fully-valid token is issued.

This is a legitimate flow (the new token reflects current membership), but it means the staleness check can be bypassed by forcing a token refresh via `/v2/` login before any scoped operation. The patch does not add a corresponding staleness check to the `/v2/` login path or the token service itself.

### Gap 3 (informational): Leeway window permits narrow bypass

`JwtLeeway` is 60 seconds (`src/common/const.go:254`). A token whose `iat` falls within 60 seconds before the project's `CreationTime` is allowed. In the typical delete-and-recreate scenario, the window is too small to be operationally significant, but it is documented in the test suite as intentional behavior.

---

## Other Token Paths — Not Affected

| Path | Generator | Subject to fix? |
|---|---|---|
| Robot account basic auth | `robot.Generate()` | N/A — not a bearer JWT, uses HMAC secret |
| OIDC CLI bearer | `oidcCli.Generate()` | N/A — uses OIDC token, not v2 JWT |
| ID token (OIDC) | `idToken.Generate()` | N/A — different token issuer, only handles `/api` and `/service/token` |
| Session | `session.Generate()` | N/A — cookie-based |
| Basic auth | `basicAuth.Generate()` | N/A — password, not token |
| Proxy cache secret | `proxyCacheSecret.Generate()` | N/A — internal secret |

The `v2Token` generator is the **only** place where Harbor-issued registry JWTs are validated, and the fix is applied there. No other generator processes Harbor v2 JWTs, so there is no sibling bypass via alternate generators.

---

## Recommendations

1. **Add `iat`-vs-`CreationTime` check to the `/v2/` login path**: In `tokenIssuedAfterProjectCreation()`, the early return on empty `ProjectName` is correct for non-project requests, but the function is also called for `/v2/` where no project check is possible. Consider separately enforcing that the token's issuing-authority is still valid (i.e., the token was issued for a project that still exists with the same identity) before accepting the authentication context.

2. **Consider checking token age at `/service/token` issuance**: Log or reject requests where the incoming authorization bearer token (used to authenticate the token-service request) predates any project in the requested scope.

3. **Rate-limit or audit `/v2/` login calls** from tokens that have no valid project scope to detect exploitation of the refresh bypass.
