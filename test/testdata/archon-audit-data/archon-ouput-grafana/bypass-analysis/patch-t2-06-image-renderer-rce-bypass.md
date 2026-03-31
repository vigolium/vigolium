# PATCH-T2-06: CVE-2025-11539 — Image Renderer RCE via /render/csv

**CVE**: CVE-2025-11539
**Severity**: CRITICAL (CVSS 9.9)
**Component**: grafana-image-renderer plugin (separate repo), referenced from Grafana core via `pkg/services/rendering/`
**Patch Version**: grafana-image-renderer >= 4.0.17
**Cluster ID**: image-renderer-path-traversal

---

## Patch Summary

CVE-2025-11539 is a path traversal to arbitrary file write vulnerability in the grafana-image-renderer plugin's HTTP API. The `/render/csv` endpoint (and potentially `/render` for PNG/PDF) accepts a `filePath` parameter that specifies where the renderer writes output. Without validation, an attacker who can reach the renderer's HTTP port can write arbitrary files on the renderer host, achieving RCE. The patch (in image-renderer v4.0.17+) adds `filePath` validation to restrict writes to allowed directories.

**The vulnerability and patch are in the image-renderer's own codebase (Node.js), not in the Grafana Go server.** However, the Grafana core codebase contains critical risk amplifiers analyzed below.

---

## Bypass Hypothesis Testing

### Hypothesis 1: Does filePath validation handle all path traversal encodings?

**Assessment**: Not directly assessable from the Grafana core repo -- the `filePath` validation logic is in the grafana-image-renderer Node.js codebase.

**Grafana core context**: In HTTP remote mode (`http_mode.go`), Grafana generates file paths server-side via `getNewFilePath()` (rendering.go:388-409). This function:
- Generates a 20-character cryptographically random string (`util.GetRandomString(20)`)
- Joins with a fixed directory (`cfg.CSVsDir`, `cfg.PDFsDir`, or `cfg.ImagesDir`)
- Calls `filepath.Abs()` to produce an absolute path

The `filePath` is **never sent to the remote renderer** in HTTP mode. Grafana writes the renderer's HTTP response body to the locally-generated path. Therefore, path traversal encodings (`%2E%2E`, `../`, `..\`) in the Grafana-to-renderer flow are irrelevant -- no user input reaches the file path.

**The attack vector is direct access to the renderer's HTTP API**, bypassing Grafana entirely.

### Hypothesis 2: Symlink resolution (TOCTOU)

**Grafana core**: `getNewFilePath()` calls `filepath.Abs()` but does NOT call `filepath.EvalSymlinks()`. If `cfg.DataPath` contains a symlink component, the output directory could resolve elsewhere. However, this requires admin-level control of the Grafana config file -- not an external attack vector.

**`writeResponseToFile()` (http_mode.go:181-219)**: Uses `os.Create(filePath)` with a `//nolint:gosec` directive. No symlink check is performed before the write. A TOCTOU attack would require creating a symlink in the output directory between `getNewFilePath()` and `os.Create()`. The random filename makes this infeasible in practice.

**Renderer side**: Must be evaluated in the grafana-image-renderer repo. If the renderer validates the directory prefix but does not resolve symlinks, an attacker could create a symlink like `/allowed/dir/symlink -> /etc/` and then request a write to `/allowed/dir/symlink/crontab`.

### Hypothesis 3: Alternative file write endpoints beyond /render/csv

**Grafana core routes**: Only one render route exists in the API (`pkg/api/api.go:599`):
```
GET /render/* -> hs.RenderHandler (requires reqSignedIn)
```
This handler (`pkg/api/render.go`) only triggers PNG/PDF rendering, not CSV. CSV rendering (`RenderCSV`) is called internally by alerting/reporting services, never exposed via a direct HTTP endpoint.

**Renderer's own HTTP API**: The protobuf definition (`rendererv2.pb.go`) shows `filePath` fields in both:
- `RenderRequest` (PNG/PDF) at field 5
- `RenderCSVRequest` (CSV) at field 2

Both endpoints in the renderer accept `filePath`. **If the patch only fixes `/render/csv`, the `/render` endpoint for PNG/PDF would remain vulnerable.** This is a critical bypass vector that must be verified in the image-renderer repo.

### Hypothesis 4: Prefix check bypass with `/allowed/../../etc/`

**Grafana core**: Not applicable -- file paths are not user-controlled.

**Renderer side**: If the renderer's validation uses a simple `startsWith()` prefix check without path canonicalization, the input `/allowed/dir/../../etc/passwd` would pass the prefix test but resolve to `/etc/passwd`. The Node.js `path.resolve()` or `path.normalize()` must be called before the prefix check, not after. Must be verified in the renderer codebase.

### Hypothesis 5: JWT token default value and forgeability

**CONFIRMED -- Critical risk amplifier.**

The default `renderer_token` is `"-"` (a single ASCII dash):
- `conf/defaults.ini:1952`: `renderer_token = -`
- `pkg/setting/setting.go:2070`: `cfg.RendererAuthToken = valueAsString(renderSec, "renderer_token", "-")`

This token is used in two ways:

1. **HTTP mode (default)**: Sent as `X-Auth-Token` header to the renderer (`http_mode.go:148`). The renderer validates this header as sole access control. With the default value `"-"`, anyone who knows this default can authenticate to the renderer's HTTP API.

2. **JWT mode** (feature flag `renderAuthJWT`, default disabled, `Expression: "false"` in registry.go:185): Used as the HMAC-HS512 signing key for JWT render tokens (`auth.go:144-146`). A 1-byte key is trivially brute-forceable.

**Attack chain**: An attacker who can reach the renderer's HTTP port (typically 8081, often `0.0.0.0`) sends a request with `X-Auth-Token: -` and a crafted `filePath` parameter to achieve arbitrary file write.

### Additional: `rendering_callback_url` / CSV render path residual bypass

The `rendererCallbackURL` (`rendering.go:85-94`) controls what URL the renderer uses to call back to Grafana for data. In HTTP mode:
- Defaults to `cfg.AppURL` if `RendererServerUrl` is set but `RendererCallbackUrl` is not
- The callback URL is sent to the renderer as a query parameter

This is not directly related to the file write vulnerability. The callback URL controls where the renderer fetches dashboard data, not where it writes output. However, if an attacker can manipulate the callback URL (e.g., via SSRF on the renderer side), they could redirect the renderer to fetch data from a malicious server that returns crafted content for the file write. This is a secondary concern, not a direct bypass.

---

## Bypass Verdict

**Verdict**: **sound** (for Grafana core) / **not fully assessable** (for renderer patch)

**Grafana core rendering integration**: The file path generation and file write operations in Grafana's `pkg/services/rendering/` are sound against CVE-2025-11539. File paths are generated internally with cryptographic randomness and fixed directory prefixes. No user input reaches the file path. The `http.ServeFile` call in `render.go:122` serves only internally-generated paths.

**Risk amplifiers that compound the renderer vulnerability**:

| Risk Factor | Severity | Detail |
|-------------|----------|--------|
| Default auth token `"-"` | CRITICAL | Renderer's HTTP API is effectively unauthenticated in default configurations |
| Renderer network exposure | HIGH | Typically binds `0.0.0.0:8081`, accessible from adjacent containers/network |
| Multiple vulnerable endpoints | HIGH | Both `/render` and `/render/csv` accept `filePath`; patch must cover both |
| No defense-in-depth path check | LOW | `writeResponseToFile` and `http.ServeFile` lack secondary path confinement |
| JWT mode weak key | MEDIUM | If `renderAuthJWT` enabled without changing token, 1-byte HMAC key is trivially forgeable |

---

## Code Paths Examined

| File | Lines | Purpose |
|------|-------|---------|
| `pkg/services/rendering/rendering.go` | 388-409 | `getNewFilePath()` -- safe random path generation |
| `pkg/services/rendering/http_mode.go` | 92-138 | `doRequestAndWriteToFile()` -- file write with `os.Create` |
| `pkg/services/rendering/http_mode.go` | 140-178 | `doRequest()` -- sends `X-Auth-Token` header |
| `pkg/services/rendering/http_mode.go` | 181-219 | `writeResponseToFile()` -- no path confinement check |
| `pkg/services/rendering/auth.go` | 56-68 | JWT verification with `RendererAuthToken` |
| `pkg/services/rendering/auth.go` | 144-147 | JWT signing with `RendererAuthToken` |
| `pkg/api/render.go` | 18-123 | `RenderHandler` -- serves file via `http.ServeFile` |
| `pkg/api/api.go` | 599 | Route: `GET /render/*` (only render route) |
| `pkg/setting/setting.go` | 2066-2081 | Rendering config defaults including `renderer_token = "-"` |
| `conf/defaults.ini` | 1951-1952 | Default `renderer_token = -` |
| `pkg/services/featuremgmt/registry.go` | 181-186 | `renderAuthJWT` feature flag (preview, disabled by default) |
| `pkg/plugins/backendplugin/pluginextensionv2/rendererv2.pb.go` | 68-82, 244-256 | Proto: `filePath` in both `RenderRequest` and `RenderCSVRequest` |

---

**Cluster ID**: image-renderer-path-traversal
**Undisclosed tag**: N/A (CVE assigned)
