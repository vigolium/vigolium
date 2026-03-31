# Round 2 Hypotheses: Image Renderer JWT Auth + ServeFile + Plugin Zip Extraction

Generated: 2026-03-21
Analyst: hyp-generator-03

---

## Area A: Image Renderer JWT Auth

### PH-01: JWT Forgery with Default Secret Allows Render Auth Bypass
- **Category**: JWT forgery / authentication bypass
- **Input path**: `pkg/services/rendering/auth.go:58-65` -- `getRenderUserFromJWT`; `pkg/setting/setting.go:2070` -- `valueAsString(renderSec, "renderer_token", "-")`
- **Assumption to test**: Operators will change `renderer_token` from its default value of `"-"` before enabling `FlagRenderAuthJWT`. The code assumes the signing secret is non-trivial.
- **Attack input**: Forge a JWT signed with HS512 using the single-byte key `"-"`:
  ```json
  header: {"alg":"HS512","typ":"JWT"}
  payload: {"RenderUser":{"org_id":1,"user_id":1,"org_role":"Admin"},"exp":<far future>}
  ```
  Present this as the `renderKey` query param on the renderer callback endpoint.
- **Expected code path**: `looksLikeJWT` returns true (token starts with `eyJ`); `getRenderUserFromJWT` calls `jwt.ParseWithClaims` with `[]byte("-")` as key; `WithValidMethods([]string{"HS512"})` is satisfied; token validates; returns `RenderUser{OrgID:1, UserID:1, OrgRole:"Admin"}` to the rendering pipeline with full admin privileges.
- **Deepening direction**: (1) Confirm `FlagRenderAuthJWT` is exposed as a feature flag that operators can enable. (2) Verify the renderer callback endpoint does not have additional IP-allowlist or network-level protection. (3) Check how `OrgRole` from `RenderUser` is consumed downstream — does it gate privileged dashboard access?
- **Priority**: HIGH

---

### PH-02: Forged or Captured JWT Replayed Indefinitely (No Revocation, No nbf)
- **Category**: JWT replay / missing claim enforcement
- **Input path**: `pkg/services/rendering/auth.go:149-164` -- `jwtRenderKeyProvider.buildJWTClaims` and `afterRequest`; `pkg/services/rendering/auth.go:56-68` -- `getRenderUserFromJWT`
- **Assumption to test**: The code assumes JWTs are short-lived enough that capture-and-replay is not practical. In reality: (1) `buildJWTClaims` sets only `ExpiresAt`, not `IssuedAt` or `NotBefore`. (2) `afterRequest` for `jwtRenderKeyProvider` is a no-op: "do nothing - the JWT will just expire" (line 162-163). (3) No token revocation list exists.
- **Attack input**: Intercept any legitimate renderer callback JWT (e.g., via a passive network tap or access to renderer logs). Re-present it against the `GetRenderUser` endpoint at any time before `ExpiresAt`. If `keyExpiry` (`cfg.RendererRenderKeyLifeTime`) is long (default needs verification), the window is large.
- **Expected code path**: `looksLikeJWT` → `jwt.ParseWithClaims` validates only `exp` claim; no `nbf` check; no replay detection; returns original `RenderUser` and grants rendering permissions. There is no mechanism to invalidate the token once issued.
- **Deepening direction**: (1) Find default value of `cfg.RendererRenderKeyLifeTime` in `setting.go`. (2) Compare with `perRequestRenderKeyProvider` which deletes the cache key in `afterRequest` (line 134-136) — jwtRenderKeyProvider is strictly weaker here. (3) Assess whether the renderer callback URL is exposed on a network interface accessible to tenants in multi-tenant deployments.
- **Priority**: HIGH

---

### PH-03: OrgRole Escalation via Forged JWT Claim
- **Category**: JWT forgery / privilege escalation
- **Input path**: `pkg/services/rendering/auth.go:23-27` -- `RenderUser` struct; `pkg/services/rendering/auth.go:67` -- `return claims.RenderUser`
- **Assumption to test**: The code assumes the `OrgRole` string extracted from a JWT is trustworthy and maps to a legitimate role. `RenderUser.OrgRole` is a plain `string` with no server-side validation against an enum after JWT extraction. Downstream code consuming `GetRenderUser` trusts this value.
- **Attack input**: Using the default secret `-` (see PH-01), forge a JWT with payload:
  ```json
  {"RenderUser":{"org_id":1,"user_id":1,"org_role":"Admin"}}
  ```
  Any org_role string is accepted — the struct tag is `json:"org_role"` with no allowlist validation.
- **Expected code path**: `getRenderUserFromJWT` returns `&RenderUser{OrgRole:"Admin"}` without checking whether "Admin" is a valid role or whether the claimed UserID actually holds that role in org 1. Downstream rendering authorization code uses this `OrgRole` to gate access to sensitive dashboards or data sources.
- **Deepening direction**: (1) Trace all callers of `GetRenderUser` to find where `RenderUser.OrgRole` is consumed and what permissions it grants. (2) Check if role validation (e.g., against `org_user` table) is performed after `GetRenderUser` returns — if not, this is a direct privilege escalation. (3) Assess whether a non-existent `UserID` (e.g., 0 or 99999) combined with `OrgRole:"Admin"` bypasses any user-existence check.
- **Priority**: HIGH

---

### PH-04: Cache Key Collision When Legitimate Render Key Starts with "eyJ"
- **Category**: authentication bypass / path confusion
- **Input path**: `pkg/services/rendering/auth.go:41` -- `looksLikeJWT(key)` and `FlagRenderAuthJWT` check; `pkg/services/rendering/auth.go:166-168` -- `looksLikeJWT`
- **Assumption to test**: `looksLikeJWT` is a purely string-prefix check (`strings.HasPrefix(key, "eyJ")`). `util.GetRandomString(32)` returns alphanumeric characters; a legitimate 32-char cache key has a non-zero probability of starting with `eyJ`. When `FlagRenderAuthJWT` is enabled, any key starting with `eyJ` is routed to JWT validation regardless of whether it is a JWT.
- **Attack input**: Generate or observe a legitimate cache-based render key that starts with `eyJ` (probability ~1 in 238,000 for random alphanumeric). When this key is submitted, `looksLikeJWT` returns true, the key is parsed as a JWT, JWT parsing fails (it's not a valid JWT), `getRenderUserFromJWT` returns nil, and the request is denied — even though a valid cache entry exists.
- **Expected code path**: Legitimate render key `eyJ<31 more chars>` → `looksLikeJWT` returns true → `getRenderUserFromJWT` → `jwt.ParseWithClaims` fails → `return nil` → `GetRenderUser` returns `(nil, false)` → renderer callback fails → render request silently errors. Denial of service for that render, with no fallback to cache lookup.
- **Deepening direction**: (1) Verify `util.GetRandomString(32)` character set to compute exact collision probability. (2) Check whether the renderer callback retries or falls back. (3) Determine whether this can be amplified: an attacker who can trigger many render requests increases the chance of hitting this path, causing intermittent render failures.
- **Priority**: MEDIUM

---

## Area B: ServeFile Path Traversal

### PH-05: Plugin-mode Renderer Returns Attacker-Controlled FilePath
- **Category**: path traversal / arbitrary file read
- **Input path**: `pkg/api/render.go:122` -- `http.ServeFile(c.Resp, c.Req, result.FilePath)`; `pkg/services/rendering/http_mode.go:95` -- `rs.getNewFilePath(renderType)` in `doRequestAndWriteToFile`
- **Assumption to test**: In HTTP mode, `result.FilePath` is always locally generated by `getNewFilePath` (a random path within `ImagesDir`/`PDFsDir`) and cannot be influenced by the renderer. However, there is a second rendering path: **plugin mode (gRPC)**. If the gRPC plugin returns a `FilePath` in its response that is not validated server-side before passing to `http.ServeFile`, a compromised or malicious plugin can return an arbitrary path such as `/etc/grafana/grafana.ini` or `/etc/passwd`.
- **Attack input**: A malicious or compromised renderer gRPC plugin whose response struct sets `FilePath = "/etc/grafana/grafana.ini"`. Grafana calls `http.ServeFile(c.Resp, c.Req, "/etc/grafana/grafana.ini")` — Go's `http.ServeFile` will read and serve the file.
- **Expected code path**: `RenderHandler` calls `hs.RenderService.Render(...)` → plugin mode rendering path → gRPC response with attacker-set `FilePath` → returned as `RenderResult{FilePath: "/etc/grafana/grafana.ini"}` → `http.ServeFile` serves the file contents to the HTTP caller.
- **Deepening direction**: (1) Locate the gRPC rendering code path in `pkg/services/rendering/` (look for `renderViaPlugin` or similar). (2) Check whether the gRPC `RenderResponse` proto includes a `FilePath` field and whether it is used directly. (3) Verify that `render.go:122` has no directory-prefix validation before `http.ServeFile`. (4) Assess whether plugin signing prevents loading an unsigned/malicious renderer plugin.
- **Priority**: HIGH

---

### PH-06: Symlink in ImagesDir Served via http.ServeFile
- **Category**: path traversal / information disclosure
- **Input path**: `pkg/api/render.go:122` -- `http.ServeFile(c.Resp, c.Req, result.FilePath)`; `pkg/services/rendering/rendering.go:388-408` -- `getNewFilePath`
- **Assumption to test**: `http.ServeFile` in Go's standard library follows symbolic links without restriction. A symlink placed in `ImagesDir` pointing to a sensitive file would be served transparently. `getNewFilePath` writes the renderer response to `<ImagesDir>/<random20>.png` — if the renderer (or another process with write access to `ImagesDir`) can replace or pre-create this file as a symlink before Grafana writes to it, the contents of the symlink target are served.
- **Attack input**: An attacker process with write access to `ImagesDir` (e.g., a compromised sidecar, a path-writable plugin, or the renderer process itself if it shares the images directory mount) creates symlink `/data/grafana/images/AAAAAAAAAAAAAAAAAAAA.png -> /etc/grafana/grafana.ini`. When a render request generates a matching filename (TOCTOU, very low probability without prediction) or if the renderer's response URL can be influenced to retrieve the symlink target, `http.ServeFile` follows the link and serves `/etc/grafana/grafana.ini`.
- **Expected code path**: `getNewFilePath` generates random path → renderer writes PNG → symlink already exists at that path (TOCTOU) → `http.ServeFile(c.Resp, c.Req, "/data/grafana/images/<name>.png")` → Go follows symlink → serves sensitive file.
- **Deepening direction**: (1) Check whether `ImagesDir` is accessible to the renderer process in both plugin and HTTP modes. (2) Verify that Go's `http.ServeFile` does NOT call `Lstat` before `Open` (it doesn't, by default). (3) Assess whether the renderer process is sandboxed (separate UID, read-only mount) in common Docker deployments.
- **Priority**: MEDIUM

---

### PH-07: SSRF via User-Controlled Render Path Sent as Callback URL to Renderer
- **Category**: Server-Side Request Forgery (SSRF)
- **Input path**: `pkg/api/render.go:90` -- `web.Params(c.Req)["*"] + queryParams`; `pkg/services/rendering/rendering.go:412-420` -- `getGrafanaCallbackURL`; `pkg/services/rendering/http_mode.go:71-72` -- `queryParams.Add("url", url)`
- **Assumption to test**: The render path from `web.Params(c.Req)["*"]` is directly concatenated into the Grafana callback URL and then sent to the remote renderer as the `url` query parameter. The renderer (a headless browser) navigates to this URL. The assumption is that `rendererCallbackURL + path` is always a Grafana-internal URL. However, if `path` contains a protocol-relative or scheme-override sequence, the resulting URL may point outside Grafana.
- **Attack input**: `GET /render/d/../../../@evil.com%2Fpath?...` — if `web.Params["*"]` captures the raw path and `getGrafanaCallbackURL` performs string concatenation without URL normalization:
  ```
  rendererCallbackURL = "http://grafana:3000/"
  path = "d/../../../@evil.com/path"
  url = "http://grafana:3000/d/../../../@evil.com/path&render=1"
  ```
  After resolution by the renderer's URL parser: may resolve to `http://evil.com/path`.
  Also test: `path = "%0d%0a%0d%0a<script>..."` for header injection if renderer logs or processes the URL.
- **Expected code path**: `RenderHandler` builds path from `web.Params["*"]` → `getGrafanaCallbackURL` string-concatenates without `url.JoinPath` → renderer receives URL with path traversal → headless browser navigates to `http://evil.com` → renderer fetches attacker's content → if renderer has access to internal network, SSRF to internal services.
- **Deepening direction**: (1) Check how `web.Params(c.Req)["*"]` handles URL-encoded sequences — does it decode before returning? (2) Verify `getGrafanaCallbackURL` uses `fmt.Sprintf("%s%s&render=1", ...)` which is pure concatenation with no URL normalization. (3) Test whether the renderer's headless browser treats `http://host/prefix/../../../@other.com` as an external URL. (4) Check for middleware that validates the render path before it reaches `RenderHandler`.
- **Priority**: MEDIUM

---

## Area C: Plugin Zip Extraction

### PH-08: TOCTOU ZipSlip — removeGitBuildFromName with Attacker-Controlled pluginDirName Escapes pluginsDir
- **Category**: TOCTOU / path traversal / ZipSlip bypass
- **Input path**: `pkg/plugins/storage/fs.go:88` -- ZipSlip check path; `pkg/plugins/storage/fs.go:99` -- actual extraction path via `removeGitBuildFromName`; `pkg/plugins/storage/fs.go:69` -- `pluginDirName := dirNameFunc(pluginID)`
- **Assumption to test**: The ZipSlip check (line 88-97) validates `filepath.Join(fs.pluginsDir, zf.Name)` — the **raw** zip entry name. The actual destination (line 99) is `filepath.Clean(filepath.Join(fs.pluginsDir, removeGitBuildFromName(zf.Name, pluginDirName)))`. These are **two different paths**. `removeGitBuildFromName` replaces the leading path component with `pluginDirName`. If `pluginDirName` itself contains `..` (derived from an attacker-supplied `pluginID`), the replacement introduces traversal that was not present in the validated path.
- **Attack input**:
  1. Supply `pluginID = "../evil"` to the plugin install endpoint (triggering `dirNameFunc("../evil") = "../evil"`).
  2. Include zip entry: `zf.Name = "legit-prefix/file.txt"`
  3. ZipSlip check: `filepath.Join(pluginsDir, "legit-prefix/file.txt")` = `pluginsDir/legit-prefix/file.txt` → **passes** (within pluginsDir).
  4. `removeGitBuildFromName("legit-prefix/file.txt", "../evil")` → `"../evil/file.txt"`
  5. `dstPath = filepath.Clean(filepath.Join(pluginsDir, "../evil/file.txt"))` = `filepath.Clean(pluginsDir + "/../evil/file.txt")` = parent of pluginsDir `/evil/file.txt` → **outside pluginsDir**.
  6. `extractFile` writes to `/evil/file.txt` with attacker-controlled content.
- **Expected code path**: ZipSlip check passes on original name → `removeGitBuildFromName` substitutes traversal-containing `pluginDirName` → `os.MkdirAll(filepath.Dir(dstPath))` creates directories outside plugins dir → `extractFile` writes arbitrary content to filesystem → code execution if written to `/etc/cron.d/`, init scripts, or a world-writable location.
- **Deepening direction**: (1) Find the plugin install API endpoint and check if `pluginID` is validated/sanitized before being passed to `Extract`. (2) Check `SimpleDirNameGeneratorFunc` — it returns `pluginID` unchanged, confirming no sanitization there. (3) Verify whether Grafana validates pluginID against `^[a-zA-Z0-9_-]+$` at a higher layer (catalog validator, install handler). (4) Check the symlink validation path: `extractSymlink(installDir, zf, dstPath)` at line 122 uses `installDir = filepath.Join(fs.pluginsDir, pluginDirName)` — if `pluginDirName = "../evil"`, `installDir` is also outside pluginsDir, making symlink validation equally compromised.
- **Priority**: HIGH

---

### PH-09: Zip Symlink TOCTOU — isSymlinkRelativeTo Check vs os.Symlink Creation
- **Category**: TOCTOU / symlink escape
- **Input path**: `pkg/plugins/storage/fs.go:121-126` -- `extractSymlink` call; `pkg/plugins/storage/fs.go:141-160` -- `extractSymlink` implementation; `pkg/plugins/storage/fs.go:165-181` -- `isSymlinkRelativeTo`
- **Assumption to test**: `isSymlinkRelativeTo(basePath, symlinkDestPath, symlinkOrigPath)` validates that the symlink target resolves within `basePath` by checking `filepath.Clean(filepath.Join(fileDir, symlinkDestPath))`. However, `basePath` here is `installDir` (line 122), not `fs.pluginsDir`. If `pluginDirName` contains `..` (see PH-08), `installDir` is itself outside `pluginsDir`, so the "confinement" check allows symlinks pointing anywhere under the attacker-controlled `installDir` path — which could be a system directory.
- **Attack input**:
  1. `pluginDirName = "../etc"` → `installDir = filepath.Join(pluginsDir, "../etc")` = `/etc`
  2. Zip contains symlink entry: `symlink_target = "passwd"`, `filePath = installDir/link`
  3. `isSymlinkRelativeTo("/etc", "passwd", "/etc/link")` → cleanPath = `/etc/passwd` → `filepath.Rel("/etc", "/etc/passwd")` = `"passwd"` → no `..` prefix → **returns true** (allowed)
  4. `os.Symlink("passwd", "/etc/link")` — creates symlink in `/etc/` pointing to `passwd`.
- **Expected code path**: `isSymlinkRelativeTo` passes because it validates relative to `installDir` not `pluginsDir`; `os.Symlink` creates a symlink inside `/etc/` or another system directory; subsequent file reads via this symlink allow privilege escalation or data exfiltration.
- **Deepening direction**: (1) Confirm that `installDir` is computed from `pluginDirName` directly in `extractFiles` (line 70: `installDir = filepath.Join(fs.pluginsDir, pluginDirName)`). (2) Trace whether `pluginDirName` is validated independently of `pluginID` validation. (3) Assess filesystem permissions — can Grafana server write to `/etc/` or other sensitive directories?
- **Priority**: MEDIUM

---

## Summary Table

| ID     | Area              | Category                        | Priority |
|--------|-------------------|---------------------------------|----------|
| PH-01  | JWT Auth          | JWT forgery / auth bypass       | HIGH     |
| PH-02  | JWT Auth          | JWT replay / no revocation      | HIGH     |
| PH-03  | JWT Auth          | OrgRole privilege escalation    | HIGH     |
| PH-04  | JWT Auth          | Cache key path confusion (DoS)  | MEDIUM   |
| PH-05  | ServeFile         | Plugin gRPC FilePath injection  | HIGH     |
| PH-06  | ServeFile         | Symlink follow in ImagesDir     | MEDIUM   |
| PH-07  | ServeFile/SSRF    | Callback URL SSRF               | MEDIUM   |
| PH-08  | Zip Extraction    | ZipSlip via pluginDirName `..`  | HIGH     |
| PH-09  | Zip Extraction    | Symlink escape via installDir   | MEDIUM   |
