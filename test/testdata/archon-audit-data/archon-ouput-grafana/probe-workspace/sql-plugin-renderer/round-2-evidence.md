# Round 2 Evidence: Image Renderer JWT Auth + ServeFile + Plugin Zip Extraction

Generated: 2026-03-21
Analyst: evidence-harvester-03

---

## Area A: Image Renderer JWT Auth

### PH-01: JWT Forgery with Default Secret Allows Render Auth Bypass

- **Status**: VALIDATED
- **Evidence**:
  - `pkg/setting/setting.go:2070`: `cfg.RendererAuthToken = valueAsString(renderSec, "renderer_token", "-")` — default is the single-byte literal `"-"`.
  - `pkg/services/featuremgmt/toggles_gen.go:70-72`: `FlagRenderAuthJWT = "renderAuthJWT"` — the flag is real and operator-enableable.
  - `pkg/services/rendering/auth.go:56-68`:
    ```go
    func (rs *RenderingService) getRenderUserFromJWT(key string) *RenderUser {
        claims := new(renderJWT)
        tkn, err := jwt.ParseWithClaims(key, claims, func(_ *jwt.Token) (any, error) {
            return []byte(rs.Cfg.RendererAuthToken), nil  // uses the raw config value
        }, jwt.WithValidMethods([]string{jwt.SigningMethodHS512.Alg()}))
        if err != nil || !tkn.Valid {
            rs.log.Error("Could not get render user from JWT", "err", err)
            return nil
        }
        return claims.RenderUser
    }
    ```
  - `pkg/services/rendering/rendering.go:113-118`: When `FlagRenderAuthJWT` is enabled globally, a `jwtRenderKeyProvider` is created with `authToken: []byte(cfg.RendererAuthToken)`. If the operator never changes the token from `"-"`, a JWT signed with `HS512` and key `"-"` passes validation.
- **Code path trace**:
  1. Attacker forges JWT: `header={"alg":"HS512","typ":"JWT"}`, `payload={"RenderUser":{"org_id":1,"user_id":1,"org_role":"Admin"}}` signed with `"-"`.
  2. Attacker presents this as `renderKey` cookie on renderer callback.
  3. `authn/clients/render.go:38` calls `GetRenderUser(ctx, key)`.
  4. `auth.go:41`: `looksLikeJWT("eyJ...")` → true; `FlagRenderAuthJWT` enabled → `getRenderUserFromJWT`.
  5. `jwt.ParseWithClaims` with key `[]byte("-")` → validates; returns `RenderUser{OrgID:1, UserID:1, OrgRole:"Admin"}`.
  6. `render.go:43-46`: `renderUsr.UserID = 1 > 0`, so the identity is built with `FetchSyncedUser: true` for user 1 — full user-level access.
- **Gaps**: No verification of whether network-level protections (IP allowlist) exist on the render callback endpoint. The callback endpoint reachability from untrusted clients is unconfirmed.
- **Confidence**: HIGH

---

### PH-02: Forged or Captured JWT Replayed Indefinitely (No Revocation, No nbf)

- **Status**: VALIDATED (with qualification on window size)
- **Evidence**:
  - `pkg/setting/setting.go:2073`: `cfg.RendererRenderKeyLifeTime = renderSec.Key("render_key_lifetime").MustDuration(5 * time.Minute)` — **default is 5 minutes**, not indefinite. This shrinks the practical replay window.
  - `pkg/services/rendering/auth.go:149-159`: `buildJWTClaims` sets only `ExpiresAt = time.Now().Add(keyExpiry)`. No `IssuedAt`, no `NotBefore`, no `jti` (token ID).
  - `pkg/services/rendering/auth.go:162-164`: `jwtRenderKeyProvider.afterRequest` is a documented no-op: `// do nothing - the JWT will just expire`.
  - Compare with `perRequestRenderKeyProvider.afterRequest` (`auth.go:134-136`): immediately deletes the cache key — token is single-use. JWT mode is strictly weaker.
- **Code path trace**:
  1. Attacker intercepts a valid JWT (e.g., via renderer process logs, network tap).
  2. Re-presents the JWT within its 5-minute `exp` window.
  3. `jwt.ParseWithClaims` validates only `exp`; no replay detection; returns original `RenderUser`.
  4. No revocation mechanism exists — the token is valid until expiry without cancellation.
- **Gaps**: Default window is 5 minutes — an operator can raise `render_key_lifetime` to hours or days, dramatically widening the replay window. Actual risk is config-dependent.
- **Confidence**: HIGH

---

### PH-03: OrgRole Escalation via Forged JWT Claim

- **Status**: VALIDATED
- **Evidence**:
  - `pkg/services/rendering/auth.go:23-27`:
    ```go
    type RenderUser struct {
        OrgID   int64  `json:"org_id"`
        UserID  int64  `json:"user_id"`
        OrgRole string `json:"org_role"`   // plain string, no enum constraint
    }
    ```
  - `pkg/services/rendering/auth.go:67`: `return claims.RenderUser` — zero OrgRole validation after JWT extraction.
  - `pkg/services/authn/clients/render.go:43-57`: downstream consumption is critical:
    ```go
    if renderUsr.UserID <= 0 {
        identityType := claims.TypeAnonymous
        if org.RoleType(renderUsr.OrgRole) == org.RoleAdmin {
            identityType = claims.TypeRenderService   // elevated identity type
        }
        return &authn.Identity{
            Type:         identityType,
            OrgRoles:     map[int64]org.RoleType{renderUsr.OrgID: org.RoleType(renderUsr.OrgRole)},
            ClientParams: authn.ClientParams{SyncPermissions: true},
        ...
    }
    ```
  - A forged JWT with `UserID=0` and `OrgRole="Admin"` yields `TypeRenderService` identity with `OrgRoles: {1: "Admin"}` and `SyncPermissions: true` — permissions are then synced from the role.
  - A forged JWT with `UserID=1` yields a full user identity for user 1 (FetchSyncedUser) with no role validation — role is not consumed in this path but user 1's actual permissions apply.
- **Code path trace**:
  1. Forge JWT with `{"org_id":1,"user_id":0,"org_role":"Admin"}` + default secret `"-"`.
  2. `getRenderUserFromJWT` returns `&RenderUser{OrgID:1, UserID:0, OrgRole:"Admin"}` — no server-side role check.
  3. `render.go:43`: `UserID=0 <= 0` → anonymous branch; `OrgRole=="Admin"` → `TypeRenderService`.
  4. Identity has `OrgRoles: {1: "Admin"}` with `SyncPermissions: true` → gains Admin permissions for org 1.
- **Gaps**: What `TypeRenderService` + Admin OrgRole ultimately allows needs tracing through the access control layer. Initial read suggests it grants org-admin-level permissions.
- **Confidence**: HIGH

---

### PH-04: Cache Key Collision When Legitimate Render Key Starts with "eyJ"

- **Status**: VALIDATED
- **Evidence**:
  - `pkg/services/rendering/auth.go:166-168`:
    ```go
    func looksLikeJWT(key string) bool {
        return strings.HasPrefix(key, "eyJ")
    }
    ```
  - `pkg/services/rendering/auth.go:103-114`: `generateAndSetRenderKey` calls `util.GetRandomString(32)`. The character set is alphanumeric (`[A-Za-z0-9]`, 62 chars). Probability of starting with exactly `eyJ` = 1/(62^3) ≈ 1/238,328 ≈ 0.00042%.
  - `pkg/services/rendering/auth.go:41-47`: If `looksLikeJWT(key)` is true AND `FlagRenderAuthJWT` is enabled, it goes directly to `getRenderUserFromJWT` with **no fallback to cache**.
  - `getRenderUserFromJWT` will fail (not a valid JWT), return `nil`, and `GetRenderUser` returns `(nil, false)` → render auth fails.
- **Code path trace**:
  1. `perRequestRenderKeyProvider.get` generates random 32-char key `eyJXXX...` (collision, ~1:238k chance).
  2. Key stored in cache; sent to renderer.
  3. Renderer presents key as cookie.
  4. `looksLikeJWT("eyJXXX...")` → true (feature flag enabled).
  5. `getRenderUserFromJWT` → `jwt.ParseWithClaims` fails (not a valid JWT structure).
  6. Returns `nil` → render request denied — DoS for that render operation.
- **Gaps**: Probability is low per request; requires `FlagRenderAuthJWT` enabled. An attacker who can trigger high render volumes increases collision frequency.
- **Confidence**: HIGH (logic is clear, impact is DoS severity)

---

## Area B: ServeFile Path Traversal

### PH-05: Plugin-mode Renderer Returns Attacker-Controlled FilePath

- **Status**: INVALIDATED
- **Evidence**:
  - `pkg/services/rendering/rendering.go:184-223` (`Run` function): Only sets `rs.renderAction = rs.renderViaHTTP` and `rs.renderCSVAction = rs.renderCSVViaHTTP` — no plugin/gRPC render action is ever registered.
  - `pkg/services/rendering/rendering.go:229-231`: `IsAvailable` / `remoteAvailable` checks only `cfg.RendererServerUrl != ""` — the HTTP remote renderer URL, not a plugin.
  - `pkg/services/rendering/` directory listing: Files present are `auth.go`, `http_mode.go`, `rendering.go`, `capabilities.go`, `interface.go`, `mock.go`. There is **no `plugin_mode.go`**, **no gRPC rendering implementation** in this package.
  - `pkg/services/rendering/http_mode.go:92-138` (`doRequestAndWriteToFile`): `filePath` is **always** obtained from `rs.getNewFilePath(renderType)` (a locally generated random path), then the HTTP response is written to it. `FilePath` in the `RenderResult` is the locally controlled path, never from an external source.
  - The `RendererPluginManager` field in `RenderingService` exists but is never invoked for actual rendering in the current codebase.
- **Code path trace**: No gRPC/plugin rendering path exists. The only active path is `renderViaHTTP` → `doRequestAndWriteToFile` → `getNewFilePath` (locally generated) → `http.ServeFile(c.Resp, c.Req, result.FilePath)` with a safe path.
- **Gaps**: `RendererPluginManager` is declared but unused for rendering — may be legacy scaffolding or planned future feature. If a gRPC plugin path is reintroduced, PH-05 would apply.
- **Confidence**: HIGH (INVALIDATED)

---

### PH-07: SSRF via User-Controlled Render Path Sent as Callback URL to Renderer

- **Status**: NEEDS-DEEPER
- **Evidence**:
  - `pkg/api/render.go:90`: `Path: web.Params(c.Req)["*"] + queryParams` — raw path from URL wildcard.
  - `pkg/services/rendering/rendering.go:420`: `return fmt.Sprintf("%s%s&render=1", rs.rendererCallbackURL, path)` — **pure string concatenation, no URL normalization**.
  - `pkg/services/rendering/http_mode.go:71-72`: `url := rs.getGrafanaCallbackURL(opts.Path); queryParams.Add("url", url)` — URL is passed as a query parameter to the renderer. The renderer's headless browser navigates to this URL.
  - The concern: if `path` contains `//evil.com/...` or `@evil.com/...`, concatenation with a base URL ending in `/` may produce a navigable external URL.
  - Example: `rendererCallbackURL = "http://grafana:3000/"`, `path = "@evil.com/dashboard?..."` → callback URL = `"http://grafana:3000/@evil.com/dashboard?...&render=1"`. A browser may parse `@` as userinfo and navigate to `evil.com`.
- **Code path trace**:
  1. Attacker requests `GET /render/d/@evil.com/path?...`.
  2. `web.Params(c.Req)["*"]` = `d/@evil.com/path` (URL-decoded by framework).
  3. `getGrafanaCallbackURL("d/@evil.com/path?...&render=1")` = `"http://grafana:3000/d/@evil.com/path?...&render=1"`.
  4. Renderer headless browser navigates to this URL — browser URL parser may resolve `@evil.com` as authority.
- **Gaps**: (1) Need to confirm whether `web.Params["*"]` performs URL decoding or passes raw. (2) Need to verify if the Grafana router's pattern match for `/render/*` rejects or strips `@` or `//` sequences. (3) Need to test renderer browser URL resolution behavior. (4) No middleware seen that validates `path` before `RenderHandler`.
- **Confidence**: MEDIUM

---

## Area C: Plugin Zip Extraction

### PH-08: TOCTOU ZipSlip — removeGitBuildFromName with Attacker-Controlled pluginDirName

- **Status**: VALIDATED (with attack surface qualification)
- **Evidence**:
  - `pkg/plugins/storage/fs.go:35-37`: `SimpleDirNameGeneratorFunc = func(pluginID string) string { return pluginID }` — **zero sanitization**.
  - `pkg/plugins/storage/fs.go:69-70`: `pluginDirName := dirNameFunc(pluginID)` / `installDir := filepath.Join(fs.pluginsDir, pluginDirName)`.
  - `pkg/plugins/storage/fs.go:88-97` (ZipSlip check): validates `filepath.Join(fs.pluginsDir, zf.Name)` — the raw zip entry name, NOT the post-`removeGitBuildFromName` path.
  - `pkg/plugins/storage/fs.go:99` (actual destination): `dstPath := filepath.Clean(filepath.Join(fs.pluginsDir, removeGitBuildFromName(zf.Name, pluginDirName)))`.
  - `pkg/plugins/storage/fs.go:223-225`: `removeGitBuildFromName` = `reGitBuild.ReplaceAllString(filename, pluginID+"/")` where `reGitBuild = regexp.MustCompile("^[a-zA-Z0-9_.-]*/")`. A zip entry `"legit-prefix/file.txt"` becomes `"../evil/file.txt"` if `pluginID = "../evil"`.
  - **Attack proof**: ZipSlip check passes on `"legit-prefix/file.txt"` (within pluginsDir), but `dstPath = filepath.Clean(pluginsDir + "/../evil/file.txt")` = one level above pluginsDir + `/evil/file.txt`.
  - **CLI path** (`pkg/cmd/grafana-cli/commands/install_command.go:79`): `pluginID := c.Args().First()` — no `../` validation. CLI operator supplying `../evil` triggers this path.
  - `pkg/plugins/manager/installer.go:38`: `ProvideInstaller` passes `storage.SimpleDirNameGeneratorFunc` directly.
  - `pkg/plugins/manager/installer.go:131`: `m.pluginStorage.Extract(ctx, pluginID, m.pluginStorageDirFunc, ...)` — no validation of pluginID before this call.
- **Code path trace**:
  1. Attacker runs `grafana-cli plugins install ../evil` (or supplies malicious ID via API/config).
  2. `pluginID = "../evil"` reaches `storage.FileSystem.Extract()`.
  3. `dirNameFunc("../evil") = "../evil"` (SimpleDirNameGeneratorFunc unchanged).
  4. Zip entry `"legit-prefix/file.txt"` passes ZipSlip check (within pluginsDir).
  5. `removeGitBuildFromName("legit-prefix/file.txt", "../evil")` = `"../evil/file.txt"`.
  6. `dstPath = filepath.Clean(pluginsDir + "/../evil/file.txt")` = `/path/to/evil/file.txt` (outside pluginsDir).
  7. `os.MkdirAll` + `extractFile` writes attacker-controlled content outside pluginsDir.
- **Gaps**: The HTTP API plugin install endpoint could not be located in `pkg/api/` — this may be in Grafana Cloud/enterprise or the plugin catalog frontend calls a separate service. The primary confirmed attack surface is the CLI. An `installPlugin.ID` in preinstall config would also work if an admin is tricked into adding `../evil`.
- **Confidence**: HIGH (code logic is fully confirmed; attack surface is CLI + config)

---

### PH-09: Zip Symlink TOCTOU — isSymlinkRelativeTo Check vs os.Symlink Creation

- **Status**: VALIDATED (dependent on PH-08)
- **Evidence**:
  - `pkg/plugins/storage/fs.go:70`: `installDir := filepath.Join(fs.pluginsDir, pluginDirName)`.
  - `pkg/plugins/storage/fs.go:122`: `extractSymlink(installDir, zf, dstPath)` — passes `installDir` as `basePath`.
  - `pkg/plugins/storage/fs.go:165-181` (`isSymlinkRelativeTo`):
    ```go
    func isSymlinkRelativeTo(basePath string, symlinkDestPath string, symlinkOrigPath string) bool {
        if filepath.IsAbs(symlinkDestPath) { return false }
        fileDir := filepath.Dir(symlinkOrigPath)
        cleanPath := filepath.Clean(filepath.Join(fileDir, symlinkDestPath))
        p, err := filepath.Rel(basePath, cleanPath)
        if err != nil { return false }
        if strings.HasPrefix(filepath.Clean(p), "..") { return false }
        return true
    }
    ```
  - **Key issue**: `basePath = installDir`. If `pluginDirName = "../etc"`, then `installDir = filepath.Join(pluginsDir, "../etc") = /etc` (assuming standard paths). The symlink validation is relative to `/etc`, not `pluginsDir`.
  - Example: `isSymlinkRelativeTo("/etc", "passwd", "/etc/link")` → `cleanPath = /etc/passwd` → `Rel("/etc", "/etc/passwd") = "passwd"` → no `..` prefix → **returns true** (allowed).
  - `os.Symlink("passwd", "/etc/link")` creates a symlink in `/etc/` (if Grafana process has write access).
- **Code path trace**:
  1. PH-08 sets `installDir = /etc` (via `pluginDirName = "../etc"`).
  2. Zip contains symlink entry with content `"passwd"` at path `"../etc/link"`.
  3. `dstPath` resolves to `/etc/link`.
  4. `isSymlinkRelativeTo("/etc", "passwd", "/etc/link")` → allowed.
  5. `os.Symlink("passwd", "/etc/link")` — symlink created.
- **Gaps**: Grafana typically runs as a non-root user; write access to `/etc/` is usually unavailable. However, if `pluginsDir` is on a writable path (e.g., `/var/lib/grafana/plugins`), `pluginDirName = "../data"` or similar could write to adjacent directories.
- **Confidence**: HIGH (code logic confirmed; practical impact limited by OS permissions)

---

## Summary Table

| ID    | Status          | Confidence | Key Finding                                                              |
|-------|-----------------|------------|--------------------------------------------------------------------------|
| PH-01 | VALIDATED       | HIGH       | Default secret `"-"` confirmed; FlagRenderAuthJWT is a real flag         |
| PH-02 | VALIDATED       | HIGH       | Default TTL=5min; afterRequest no-op confirmed; no revocation            |
| PH-03 | VALIDATED       | HIGH       | OrgRole string unvalidated; TypeRenderService identity with Admin role   |
| PH-04 | VALIDATED       | HIGH       | `looksLikeJWT` is prefix-only; no fallback to cache on JWT parse failure |
| PH-05 | INVALIDATED     | HIGH       | No gRPC/plugin rendering path exists; HTTP mode always uses local path   |
| PH-07 | NEEDS-DEEPER    | MEDIUM     | Pure string concat confirmed; browser URL parsing behavior unverified    |
| PH-08 | VALIDATED       | HIGH       | ZipSlip via `removeGitBuildFromName` + unsanitized pluginID confirmed    |
| PH-09 | VALIDATED       | HIGH       | isSymlinkRelativeTo validates against installDir, not pluginsDir         |
