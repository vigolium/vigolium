# Round 1 Evidence: Snapshot Auth Bypass, Avatar Anonymous Bypass, Alerting Secrets

---

### PH-01: K8s Snapshot Delete-by-DeleteKey Cross-Org Deletion
**Status: VALIDATED**

**Evidence:**
1. K8s route at `routes.go:257-283` performs RBAC check for `ActionSnapshotsDelete` (line 266) but does NOT check org membership.
2. The handler calls `dashboardsnapshots.DeleteWithKey(ctx, key, service)` at line 275.
3. `DeleteWithKey()` at `service.go:223-240` constructs `GetDashboardSnapshotQuery{DeleteKey: key}` and passes it to `GetDashboardSnapshot()`.
4. The database layer at `database.go:89-108` does `sess.Get(&snapshot)` with only the DeleteKey field set -- NO org_id in the WHERE clause.
5. **Contrast with REST API**: `DeleteDashboardSnapshot()` at `dashboard_snapshot.go:218` explicitly checks `queryResult.OrgID != c.OrgID`.
6. **Contrast with K8s create**: The create handler at `routes.go:131-140` explicitly validates `info.OrgID != user.GetOrgID()`.

**Attack chain**: User in Org-B with `ActionSnapshotsDelete` permission obtains a deleteKey from Org-A (via logs, shared URLs, or intercepted API responses), then calls the K8s delete endpoint to delete Org-A's snapshot.

**Severity**: MEDIUM (requires deleteKey knowledge -- 190-bit entropy)

---

### PH-02: REST Snapshot GET Has No Auth Middleware
**Status: VALIDATED**

**Evidence:**
1. `api.go:611`: `r.Get("/api/snapshots/:key", routing.Wrap(hs.GetDashboardSnapshot))` -- NO middleware at all (no reqSignedIn, no reqSnapshotPublicMode, nothing).
2. The handler at `dashboard_snapshot.go:112-150` only checks that the key is non-empty and the snapshot hasn't expired.
3. No org check, no user check, no RBAC check.
4. This is BY DESIGN -- snapshots are intended to be shared via their key as a bearer token.
5. However, the key is only 32 chars alphanumeric (~190 bits), and keys appear in URLs (`/dashboard/snapshot/:key`).

**Security assessment**: This is intentional design for shareability. The key provides the authentication. Risk is LOW unless keys are leaked via logs, referrer headers, or shared URLs.

**Severity**: LOW (by design, key has high entropy)

---

### PH-03: Avatar Anonymous Bypass for DoS
**Status: VALIDATED**

**Evidence:**
1. `api.go:605`: `r.Get("/avatar/:hash", requestmeta.SetSLOGroup(requestmeta.SLOGroupHighSlow), reqSignedIn, hs.AvatarCacheServer.Handler)` -- uses `reqSignedIn`.
2. `middleware.go:19-20`: `ReqSignedIn = Auth(&AuthOptions{ReqSignedIn: true})` and `ReqSignedInNoAnonymous = Auth(&AuthOptions{ReqSignedIn: true, ReqNoAnonynmous: true})`.
3. `auth.go:216`: `requireLogin := !c.AllowAnonymous || forceLogin || options.ReqNoAnonynmous` -- when AllowAnonymous=true and ReqNoAnonynmous=false, requireLogin=false. Anonymous user passes.
4. Avatar handler at `avatar.go:104-126` makes outbound HTTP to Gravatar on cache miss (line 155 -> `avatar.update()` -> `avatarFetch()` -> `performGet()`).
5. LRU cache is bounded to 2000 entries (`avatar.go:184`), but each miss triggers two HTTP requests to Gravatar (lines 285-289 in avatarFetch).
6. Hash validation at `avatar.go:107` only allows 32-char hex -- but there are 16^32 = 3.4 * 10^38 possible hashes, far more than the 2000 cache entries.

**Attack**: Unauthenticated attacker sends requests with unique valid hashes, each triggering 2 outbound HTTP requests. At high concurrency, this exhausts goroutines and creates outbound connection pressure (SSRF-adjacent DoS).

**Severity**: HIGH (when anonymous auth is enabled)

---

### PH-04: Other reqSignedIn Routes Vulnerable to Anonymous Bypass
**Status: VALIDATED**

**Evidence:**
From api.go, notable routes using `reqSignedIn` (accessible to anonymous users when anon auth enabled):
1. `line 599`: `r.Get("/render/*", ... reqSignedIn, hs.RenderHandler)` -- image rendering
2. `line 602`: `r.Any("/api/gnet/*", ... reqSignedIn, hs.ProxyGnetRequest)` -- grafana.net proxy
3. `line 605`: `r.Get("/avatar/:hash", ... reqSignedIn, ...)` -- avatar (the known bypass)
4. `line 608`: `r.Get("/api/snapshot/shared-options/", reqSignedIn, hs.GetSharingOptions)` -- config disclosure
5. Lines 111, 151, 176-190, 218-228: Various dashboard/playlist/alerting index pages

Routes using `reqSignedInNoAnonymous` (~7 total):
- `line 93`: `/profile/`
- `line 94`: `/profile/password`
- `line 96`: `/profile/switch-org/:id`
- `line 239`: `/user/email/update`
- `line 240`: `/api/user/email/start-verify`
- `line 317`: An API group

**Most concerning**: `/render/*` (line 599) -- if anonymous users can access the render endpoint, they could trigger image rendering operations, consuming server resources. `/api/gnet/*` (line 602) -- proxies to grafana.net, allowing anonymous users to make requests through Grafana as a proxy.

**Severity**: MEDIUM (depends on which routes expose sensitive functionality to anonymous)

---

### PH-05: K8s Snapshot Create Leaks DeleteKey in Response
**Status: VALIDATED**

**Evidence:**
1. `routes.go:225-231`: Response includes `DeleteKey: cmd.DeleteKey` in plaintext JSON.
2. `dashboard_snapshot.go` REST create: The REST API also returns deleteKey (via `service.go:141-143`), and additionally returns the `DeleteURL` which contains the deleteKey.
3. Both APIs leak the deleteKey to the creator, which is by design. However, if the response is logged, cached by proxies, or intercepted, the deleteKey enables cross-org deletion via PH-01.

**Severity**: LOW (by design; risk is in combination with PH-01)

---

### PH-06: SnapshotPublicMode Allows Unauthenticated Deletion
**Status: VALIDATED**

**Evidence:**
1. `auth.go:255-268`: `SnapshotPublicModeOrDelete` returns immediately when `cfg.SnapshotPublicMode` is true (line 257), bypassing all auth checks.
2. `api.go:615`: `r.Get("/api/snapshots-delete/:deleteKey", reqSnapshotPublicModeOrDelete, routing.Wrap(hs.DeleteDashboardSnapshotByDeleteKey))` -- uses this middleware.
3. When SnapshotPublicMode=true, ANY unauthenticated user can delete any snapshot if they know the deleteKey.
4. Default: `SnapshotPublicMode` is false, so this is only a risk when explicitly enabled.

**Severity**: LOW (requires non-default config + deleteKey knowledge)

---

### PH-07: Alerting Contact Point Secret Leakage via Error Messages
**Status: NEEDS-DEEPER**

**Evidence:**
1. `api_alertmanager.go:312-333`: The `newTestReceiversResult()` function maps test results, including `configs[jx].Error = config.Error` (line 327).
2. The `Error` field is a string from `alertingNotify.TestReceiversResult.Configs[].Error`.
3. If a webhook/API call fails with an error that includes the URL (which may contain API keys as query parameters or path segments), that error string would be returned to the caller.
4. The VictorOps URL field is typed as `Secret` in the schema (contact_points.go:299), so it SHOULD be redacted in normal GET responses.
5. However, the test-receiver path processes secrets via `ProcessSecureSettings` (line 237), meaning the actual secret values are used for the test call, and any resulting error messages could contain those values.

**What's needed**: Trace into `alertingNotify.TestReceivers` to see how error messages are constructed and whether they include URLs/API keys. This is in the `github.com/grafana/alerting` external package.

**Severity**: MEDIUM (if confirmed)

---

### PH-08: Avatar SSRF via Hash-Controlled URL
**Status: INVALIDATED**

**Evidence:**
1. `avatar.go:31`: `gravatarSource = "https://secure.gravatar.com/avatar/"` -- hardcoded base URL.
2. `avatar.go:74`: URL constructed as `baseUrl + a.hash + "?"` -- hash is appended to the path.
3. `avatar.go:107`: Hash validated as exactly 32-char hex via `validMD5.MatchString(hash)`.
4. The hash is constrained to `[a-fA-F0-9]{32}` which cannot break out of the URL path to redirect to a different host.
5. No SSRF risk -- the destination is always `secure.gravatar.com`.

**Severity**: N/A (invalidated)
