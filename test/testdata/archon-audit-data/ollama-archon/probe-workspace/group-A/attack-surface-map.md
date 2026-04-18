# Attack Surface Map: Group A — Registry / Download / Blob Store

## Entry Points

- `server/images.go:853` — `pullModelManifest` — accepts registry hostname from `model.Name.BaseURL()`, issues `io.ReadAll(resp.Body)` with no size cap on manifest response
- `server/images.go:633` — `hasTensorLayers` dispatch within `PullModel` — gate-condition that flips entire pull pipeline to `pullWithTransfer` fast path when ANY layer has `MediaTypeImageTensor`; attacker controls all manifest layer fields
- `server/images.go:721` — `pullWithTransfer` — accepts `[]manifest.Layer` (layer.Digest, layer.Size) from a remote manifest without calling `manifest.BlobsPath()` on digests; delegates to `transfer.Download`
- `server/images.go:795` — `pushWithTransfer` — reads blob files from local disk using `digestToPath(blob.Digest)` without canonicalization for the upload side
- `server/images.go:595` — `PullModel` — entry from `routes.go:953`; registry host comes from `req.Name` JSON field; no host allowlist check at this layer
- `server/download.go:468` — `downloadBlob` — `opts.digest` from layer manifest; passes through `manifest.BlobsPath(digest)` (protected on legacy path); `os.Stat(fp)` cache-hit returns immediately without hashing
- `server/download.go:331` — `blobDownload.downloadChunk` — HTTP GET with `Range: bytes=X-Y`; response `StatusCode` is NOT validated (200 vs 206); `Content-Range` header NOT validated
- `server/upload.go:56` — `StartUpload` — `layer.Digest` from local manifest; goes through `manifest.BlobsPath` (protected)
- `server/internal/registry/server.go:259` — `handlePull` — JSON body `model`/`name` field decoded via `decodeUserJSON`; body read via `json.NewDecoder(r.Body)` with NO size limit; dispatched BEFORE gin middleware chain when `OLLAMA_EXPERIMENT=client2`
- `server/internal/registry/server.go:230` — `handleDelete` — same pre-gin dispatch, `DELETE` body field
- `server/internal/client/ollama/registry.go:464` — `Registry.Pull` — `io.ReadAll(res.Body)` on manifest response at line ~796 with no size cap; layer digests stored in `blob.DiskCache` directly
- `server/internal/client/ollama/registry.go:780` — `Registry.Resolve` — `io.ReadAll(res.Body)` on manifest body; no size limit
- `manifest/paths.go:40` — `BlobsPath` — validates digest regex `^sha256[:-][0-9a-fA-F]{64}$`; this is the ONLY place the validation happens; entire fast-path bypasses it
- `x/imagegen/transfer/transfer.go:165` — `digestToPath` — raw `strings.Replace(digest, ":", "-", 1)` with NO regex, no length check, no `filepath.IsLocal`; the core bypass from CVE-2024-37032
- `x/imagegen/transfer/download.go:43` — `download` — cache-hit check at line 58: `os.Stat(filepath.Join(opts.DestDir, digestToPath(b.Digest)))` compares `fi.Size() == b.Size` — no hash verification of existing file
- `x/imagegen/transfer/download.go:212` — `downloader.save` — `os.MkdirAll(filepath.Dir(dest), 0o755)` then `os.Create(tmp)` where `dest = filepath.Join(d.destDir, digestToPath(blob.Digest))` — path traversal write sink
- `x/imagegen/transfer/download.go:326` — `downloader.resolve` — follows HTTP redirects up to 10 hops; on non-same-host redirect returns the redirect URL directly to use as blob download URL; no scheme validation on redirect target
- `server/auth.go:53` — `getAuthorizationToken` — `io.ReadAll(response.Body)` with no size cap on token response body (DFD-13)
- `server/images.go:888` — `makeRequestWithRetry` — on 401, calls `parseRegistryChallenge` then `getAuthorizationToken`; the realm host check depends on `getAuthorizationToken` implementation

## Trust Boundary Crossings

- **B3a** — `pullModelManifest` receives manifest JSON from remote registry → `json.Unmarshal` → `manifest.Layer` struct; layer `Digest` field is attacker-controlled string
- **B3b** — `hasTensorLayers` checks `layer.MediaType == MediaTypeImageTensor`; a single `true` result redirects ALL digests to the unvalidated fast path (`pullWithTransfer`)
- **B3c** — `pullWithTransfer` passes `layer.Digest` directly into `transfer.Blob{Digest: layer.Digest}` — crosses from "model name validated" to "digest unvalidated" at this boundary
- **B3d** — `digestToPath` converts a raw string to a filesystem path segment — crosses from attacker-controlled string to OS file path with no validation
- **B4a** — `downloader.resolve` follows redirects; when redirect goes off-host, the new URL becomes the download endpoint — crosses from registry-controlled URL to CDN-controlled URL; scheme not re-validated
- **B4b** — `blobDownload.downloadChunk` sends `Range: bytes=X-Y`; server response content is written to `io.NewOffsetWriter(file, part.StartsAt())` without validating response `StatusCode == 206` or `Content-Range` header
- **B5a** — `downloadBlob` cache-hit: `os.Stat(fp)` success → returns `cacheHit=true` without any hash verification; bytes enter "verified blob" trust zone without being verified
- **B5b** — `transfer/download.go:58` cache-hit: `fi.Size() == b.Size` check only; no digest hash; file content enters "verified blob" trust zone without hash verification
- **B5c** — `Registry.Pull` in `registry.go:516` cache-hit: `c.Get(l.Digest)` returns `info.Size == l.Size` match → `ErrCached` path; no re-hash
- **B6a** — `server/internal/registry/server.go:114` dispatches `/api/pull` and `/api/delete` BEFORE the gin middleware; `allowedHostsMiddleware` (B1) is never reached for these routes when `OLLAMA_EXPERIMENT=client2`
- **B7a** — `getAuthorizationToken` receives `WWW-Authenticate` realm from registry; `parseRegistryChallenge` extracts realm URL; realm host is checked against original host in `server/auth.go` but this check does NOT exist in the parallel `transfer/transfer.go:parseAuthChallenge` path which is used by `pullWithTransfer`

## Auth / AuthZ Decision Points

- `server/auth.go:53` — `getAuthorizationToken` — sends ed25519-signed auth to realm URL; realm host validated against original host (server-side `server/auth.go` version only; `transfer/transfer.go:parseAuthChallenge` has no such check)
- `server/images.go:615` — HTTP scheme check: `if n.ProtocolScheme == "http" && !regOpts.Insecure { return errInsecureProtocol }` — only enforces TLS on initial manifest fetch; redirect targets NOT re-checked
- `server/download.go:240` — `CheckRedirect` closure in `run()`: allows same-hostname redirects AND returns `http.ErrUseLastResponse` for different-hostname (stops at first off-host redirect but does NOT validate TLS on the resulting direct URL)
- `x/imagegen/transfer/download.go:186` — `req.Header.Set("Authorization", "Bearer "+*d.token)` — auth token is only sent when `u.Host == baseURL.Host`; after off-host redirect no auth is sent (correct, but no TLS validation of the CDN URL)
- `server/internal/registry/server.go:114` — NO auth gate on `/api/pull` and `/api/delete` when dispatched via the `registry.Local` handler path (client2 experiment)
- `manifest/paths.go:40` — `BlobsPath` — single digest regex gate; this is the entire trust chain for blob path construction on the legacy path; absent on the tensor fast path

## Validation / Sanitization Functions

- `manifest/paths.go:40` — `BlobsPath(digest)` — regex `^sha256[:-][0-9a-fA-F]{64}$`; validates digest before building filesystem path; NOT called by `pullWithTransfer`/`pushWithTransfer`/`digestToPath`
- `types/model/name.go:344` — `isValidPart` — validates model name components (host/namespace/model/tag); restricts to `[A-Za-z0-9_-.]` plus limited separators; does NOT validate digest strings
- `server/images.go:615` — insecure protocol check — rejects `http://` scheme unless `Insecure=true`; bypassed on redirect targets
- `x/imagegen/transfer/download.go:257` — inline sha256 hash check: `if got := fmt.Sprintf("sha256:%x", h.Sum(nil)); got != blob.Digest` — hash check at end of `save()`; BUT only fires when `Digest` is a valid sha256 hex (a path-traversal digest like `sha256:../../../etc` will never match, so the `os.Rename` does not run, BUT the partial `.tmp` file persists)
- `x/imagegen/transfer/download.go:58` — size-only cache check: `fi.Size() == b.Size` — no hash; an attacker-planted file of correct size passes
- `server/download.go:473` — `manifest.BlobsPath(opts.digest)` — called in legacy `downloadBlob`; validates digest before use; protected path

## Layer Trust Chain

| From Layer | To Layer | Trust Assumption | Holds for ALL paths? | Alternate Paths that Skip This Layer? |
|-----------|---------|-----------------|:---:|---|
| HTTP client (gin handler, PullHandler) | `PullModel` | model name is syntactically valid per `parseNormalizePullModelRef` | YES — both gin and client2 paths parse name | client2 `/api/pull` skips `allowedHostsMiddleware` before reaching PullModel |
| `PullModel` | `pullModelManifest` | registry host is trusted (attacker controlled but TLS enforced) | NO — no host allowlist; any IP including 169.254.169.254 is reachable | SSRF: `POST /api/pull {"name":"169.254.169.254/x:latest"}` |
| `pullModelManifest` → `hasTensorLayers` | `pullWithTransfer` | layer digests will be validated by `manifest.BlobsPath` | NO — tensor-path skips BlobsPath | ANY manifest with `application/vnd.ollama.image.tensor` layer flips to fast path |
| `pullWithTransfer` | `transfer.Download` | `transfer.Blob.Digest` will be validated inside transfer | NO — `digestToPath` does raw string substitution only | Path traversal write: `sha256:../../../etc/cron.d/evil` → valid-looking Blob.Digest |
| `transfer.Download` | `downloader.save` | existing file at `dest` is genuine if `fi.Size() == b.Size` | NO — size-only cache check, no hash | Pre-staged file of correct size accepted without hash verification |
| `blobDownload.downloadChunk` | `io.NewOffsetWriter(file, part.StartsAt())` | HTTP 206 response covers the requested byte range | NO — `resp.StatusCode` and `Content-Range` not validated | Server returning 200+full blob or wrong range → wrong bytes at wrong offset |
| `downloadBlob` cache-hit | blob store trusted | existing blob file is correct (hash not re-verified) | NO — `os.Stat` success only | File-system write by co-tenant → arbitrary model substitution |
| `getAuthorizationToken` (server/auth.go) | `getAuthorizationToken` (transfer/transfer.go) | realm host checked against original host | NO — only in server/auth.go; transfer's `parseAuthChallenge` has NO realm host check | `pullWithTransfer` uses `transfer.GetToken` callback → `getAuthorizationToken` in `server/images.go:755` → calls `server/auth.go:getAuthorizationToken` (protected) but `transfer/transfer.go:parseAuthChallenge` has no check |
| `registry.Local.ServeHTTP` | gin `allowedHostsMiddleware` | all requests pass DNS-rebind gate | NO — when `OLLAMA_EXPERIMENT=client2`, `/api/pull` and `/api/delete` are handled by `registry.Local` BEFORE gin chain | Setting `OLLAMA_EXPERIMENT=client2` bypasses `allowedHostsMiddleware` for pull/delete |
| `io.ReadAll(manifest resp.Body)` | `json.Unmarshal` | manifest response body is bounded | NO — no `io.LimitReader`; malicious registry can return arbitrarily large body | OOM DoS: manifest with 10 MB JSON body |
| `io.ReadAll(token resp.Body)` | `json.Unmarshal` | token response is bounded | NO — `server/auth.go:81` has no size cap | OOM DoS via malicious auth realm server |

## Trust Chain Gaps (rows where "Alternate Paths" column is NOT empty)

1. **pullWithTransfer digest bypass** — `pullWithTransfer` at `server/images.go:721` uses `layer.Digest` directly in `transfer.Blob{Digest: layer.Digest}` without calling `manifest.BlobsPath()`. Combined with `digestToPath`'s raw `strings.Replace`, ANY manifest with a tensor layer can deliver a path-traversal digest. This is the core CVE-2024-37032 bypass already identified; find variant chains (e.g., combined with client2 DNS rebind bypass).

2. **transfer size-only cache-hit** — `downloader.download` at `x/imagegen/transfer/download.go:58` skips a blob if `fi.Size() == b.Size`; no hash check. An attacker with any write path to `$OLLAMA_MODELS/blobs/` (co-tenant, prior partial write, backup restore) can pre-stage a malicious file of the correct size and have it accepted as verified.

3. **legacy downloadBlob cache-hit** — `downloadBlob` at `server/download.go:478-491` returns `cacheHit=true` on `os.Stat` success with no hash. The legacy path had `verifyBlob` as a second line, but `skipVerify[digest] = cacheHit` then skips verification. Post-`2aee6c17` branch: `verifyBlob` is dead code; cache-hit has NO verification at all.

4. **HTTP 206/Content-Range not validated** — `blobDownload.downloadChunk` at `server/download.go:331-389` sends `Range:` header but accepts ANY response (200, 206, other); `Content-Range` header in response is never compared to requested range. A malicious origin can return wrong bytes at wrong offsets.

5. **`io.ReadAll` with no cap on manifest/token responses** — `pullModelManifest` (`server/images.go:864`) and `getAuthorizationToken` (`server/auth.go:81`) and `Registry.Resolve` (`server/internal/client/ollama/registry.go:~796`) all call `io.ReadAll` on registry response bodies without `io.LimitReader`. A malicious registry serves multi-GB response → OOM.

6. **client2 `/api/pull` and `/api/delete` bypass `allowedHostsMiddleware`** — `registry.Local.serveHTTP` dispatches `/api/pull` and `/api/delete` synchronously before the gin chain when `OLLAMA_EXPERIMENT=client2`. The DNS-rebinding mitigation (`allowedHostsMiddleware`) never runs for these endpoints.

7. **transfer `parseAuthChallenge` has no realm-host check** — `x/imagegen/transfer/transfer.go:172` parses `WWW-Authenticate` header with no realm-host validation. If a redirect during `downloader.resolve` delivers a 401 challenge with an attacker-controlled realm, tokens are sent to the attacker. (Different from server-side fix `7601f0e9` which only hardened `server/auth.go`; the `pullWithTransfer` path uses the `getToken` callback in `server/images.go:755` which calls `getAuthorizationToken` in `server/auth.go` — so realm host IS checked there. But the `resolve()` loop in `transfer/download.go:350` also calls `d.getToken` on 401 — it goes through the same server-side protected path. Gap is narrower than initially apparent: focus on redirect+scheme bypasses instead.)

8. **SSRF via registry host** — `pullModelManifest` builds URL from `n.BaseURL()` which uses the user-supplied host; no host allowlist. `POST /api/pull {"name":"169.254.169.254/library/x:latest"}` probes IMDS. Error messages include registry response data.

9. **Redirect target scheme not re-validated** — `blobDownload.run()` at `server/download.go:229-270` follows a redirect to a `directURL`; the redirect target's scheme is never re-checked against `regOpts.Insecure`. A registry can redirect `https://` blob download to `http://` CDN, delivering unencrypted data that is then hashed (hash is correct for the bytes received, but MITM can tamper in transit).
