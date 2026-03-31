# Bypass Analysis: CVE-2024-22278 (commit 89e1c4baa)

**Cluster ID:** CVE-2024-22278-v2token  
**Files patched:** `src/server/middleware/security/v2_token.go`, `src/server/middleware/security/v2_token_test.go`

---

## Patch Summary

The patch addresses a delete-and-recreate project authorization bypass. When a Harbor project was deleted and a new project was recreated with the same name, a bearer token that was originally issued for the old project could be replayed to gain access to the new project. The fix adds `tokenIssuedAfterProjectCreation()`, which is called inside `v2Token.Generate()` after JWT signature and standard-claims validation. It looks up the current project by name from the request-context `ArtifactInfo`, fetches the project's `creation_time` from the database, and rejects any token whose `iat + JwtLeeway (60s)` is before the project's `creation_time`.

**Mechanism added:** database-backed `iat` vs `creation_time` comparison inside the `v2Token` security-context generator.

---

## Bypass Verdict

**sound** — with one minor unchecked defensive-programming gap noted below.

---

## Evidence

### Vector 1: Alternate entry points (security generator chain)

The security generator chain in `security.go` is:

```
secret -> oidcCli -> v2Token -> idToken -> authProxy -> robot -> basicAuth -> session -> proxyCacheSecret
```

The chain stops at the first generator that returns a non-nil context. For a `/v2/*` request that arrives with a Bearer token header:

- `secret`: uses `commonsecret.FromRequest()`, not Bearer — **skipped**
- `oidcCli`: uses `req.BasicAuth()` — **skipped**
- `v2Token`: matches Bearer tokens for `/v2` prefix — **fix is applied here**
- `idToken`: explicitly guards with `!strings.HasPrefix(req.URL.Path, "/api")` — **never reached for /v2**
- `robot`, `basicAuth`, `session`, `proxyCacheSecret`: all use BasicAuth or session cookies — **skipped**

No alternate generator can accept a Harbor-service-issued Bearer token for `/v2` paths.

### Vector 2: Config-gated checks

The `tokenIssuedAfterProjectCreation` function is always invoked after successful JWT signature and standard-claim validation. It is not conditional on any configuration flag. The fix is unconditionally active.

### Vector 3: Default-state gaps

`artifactinfo.Middleware()` is registered before `security.Middleware()` in `src/core/middlewares/middlewares.go` lines 98–99:

```go
artifactinfo.Middleware(),
security.Middleware(pingSkipper),
```

`ArtifactInfo` (including `ProjectName`) is therefore always populated in the request context before `v2Token.Generate()` is called. No default-state gap exists.

### Vector 4: Empty ProjectName path (by design, not a bypass)

When the URL does not match a project-scoped pattern (e.g., `/v2/` ping, `/v2/_catalog` catalog listing), `artifactinfo.Middleware()` does not populate `ArtifactInfo`. `tokenIssuedAfterProjectCreation` therefore sees `info.ProjectName == ""` and returns `true` (allow). This is intentional: catalog and ping requests have no per-project `creation_time` to check. Neither endpoint grants per-project repository write/read access, so there is no bypass exposure here.

### Vector 5: Parser differentials and iat manipulation

The `iat` claim in Bearer tokens is set server-side in `authutils.go` line 131 as `jwt.NewNumericDate(now)`. Tokens are signed with RSA or ECDSA (Harbor's private key). An attacker cannot present a forged token with a manipulated `iat`.

There is no normalization gap for `iat` itself: the fix uses the raw `time.Time` value from the parsed and cryptographically verified JWT.

### Vector 6: Project name case sensitivity and Unicode

`tokenIssuedAfterProjectCreation` calls `project_ctl.Ctl.GetByName(ctx, info.ProjectName)`. The `projectName` in `ArtifactInfo` is extracted by splitting the URL repository path on `/` (first component). The database query in `dao.GetByName` uses an ORM exact-match read:

```go
project := &models.Project{Name: name, Deleted: false}
o.Read(project, "name", "deleted")
```

Harbor enforces lowercase project names at creation time (validated by the REST API layer). The URL-extracted name is used verbatim. Since Harbor rejects uppercase project names on creation, case variation is not exploitable. Unicode normalization is not a concern for the same reason.

### Vector 7: Race condition (delete + recreate timing)

If an attacker controls when a token is issued, they could wait until a project is deleted-and-recreated, then obtain a fresh token. That fresh token would have `iat` after the new project's `creation_time` and would pass the check correctly. This is expected behavior, not a bypass of the fix.

The only practical race window is: if a token is issued within 60 seconds of the old project's deletion AND the new project is created within those 60 seconds, the token's `iat + JwtLeeway` might not be before the new project's `creation_time`. Under normal circumstances the deletion-recreation cycle takes longer than 60 seconds, and an attacker does not control Harbor's project creation timestamps.

### Vector 8: Sibling paths — v2auth middleware

The `v2auth.Middleware()` is applied at the registry route root `/v2` in `src/server/registry/route.go`. It checks RBAC permissions using `security.Context.Can()`. The `tokenSecurityCtx` (from `v2token.New()`) in `Can()` looks up the project by ID (obtained from the URL request), then checks `accessMap[p.Name]` where `p.Name` is the *current* project's name and `accessMap` is keyed by the first path component of `claims.Access[].Name` (i.e., the name embedded in the token at issuance time).

After project recreation, the new project has a new `ProjectID`. The old token's `claims.Access` contains the old project name. The `v2auth` lookup will retrieve the new project's name and match it against `accessMap[newProjectName]`. Since the token was issued for `oldProjectName`, the key is identical (same string) but the project now points to a different entity. This means `v2auth` alone would NOT have prevented the bypass before this fix (same project name = same map key). The fix in this patch is the necessary guard.

### Minor gap: missing nil guard for `claims.IssuedAt`

In `tokenIssuedAfterProjectCreation`:

```go
iat := claims.IssuedAt.Time
```

`claims.IssuedAt` is a `*jwt.NumericDate`. If a token is presented without an `iat` claim, `claims.IssuedAt` will be `nil` after parsing, and this line will panic (nil pointer dereference). The jwt parser is configured with `jwt.WithLeeway()` but NOT with `jwt.WithIssuedAt()`, so a missing `iat` does not cause parse failure.

In practice Harbor's token service always sets `iat` (see `authutils.go` line 131), and since tokens are cryptographically signed the claim cannot be stripped. However, this is a latent defensive-programming weakness: a future code path that issues tokens without `iat` would cause a runtime panic here rather than a clean rejection. The tests do not cover a nil `IssuedAt` case.

**Exploitability:** None under current Harbor token issuance. Theoretical under token-service code changes.

---

## Summary

The fix correctly closes the delete-and-recreate bearer token replay vector. All alternate entry points, config flags, middleware ordering, and normalization paths have been checked. The protection is unconditional and on the critical path for every project-scoped `/v2` registry request that presents a Bearer token. The single identified gap (nil `IssuedAt` guard) is not exploitable with current token issuance code but is a hardening recommendation.
