# Round 2 Hypotheses — Contradiction Reasoner

Reasoning model: Abductive / Contradiction (identify unstated assumptions in existing defenses, find where those assumptions fail)

## PH-08: Contradiction in BlobsPath "validates all digests" assumption — pushWithTransfer reads via unvalidated digestToPath (HIGH)

**Stated protection assumption**: `manifest.BlobsPath` validates all digest-to-path conversions; any blob operation goes through this validated gate.

**Contradiction**: `pushWithTransfer` at `server/images.go:795-851` builds `blobs[i].Digest = layer.Digest` and passes to `transfer.Upload`. The upload opens the source file via `os.Open(filepath.Join(u.srcDir, digestToPath(blob.Digest)))` at `x/imagegen/transfer/upload.go:181`.

If `layer.Digest` in the locally stored manifest has been tampered (e.g., via PH-01 writing a crafted manifest file, or via a `POST /api/create` that produces a manifest with a traversal digest), then `pushWithTransfer` will `os.Open` a file OUTSIDE `$OLLAMA_MODELS/blobs/` and send its contents to the registry.

**Attack chain**: 
1. Use PH-01 (path traversal write) to plant a crafted manifest at `$OLLAMA_MODELS/manifests/<host>/<ns>/<model>/<tag>` containing a traversal digest
2. Call `POST /api/push {"name":"<model>"}` 
3. `pushWithTransfer` opens `os.Open(filepath.Join(srcDir, digestToPath("sha256:../../../etc/shadow")))` → arbitrary file read + exfiltration to attacker's registry

**VALIDATED**: `x/imagegen/transfer/upload.go:181` confirmed: `os.Open(filepath.Join(u.srcDir, digestToPath(blob.Digest)))`. `pushWithTransfer` at `images.go:796-803` copies `layer.Digest` directly to `blobs[i].Digest` without `BlobsPath` call.

**Severity**: HIGH — arbitrary file read via push operation when manifest is compromised.

---

## PH-09: Contradiction in "realm host check prevents auth token theft" — transfer path parseAuthChallenge has no check (HIGH)

**Stated protection assumption**: Fix `7601f0e9` added realm-host-match check in `getAuthorizationToken` to prevent Bearer token being sent to attacker-controlled auth endpoints.

**Contradiction**: The transfer package's `parseAuthChallenge` function (at `x/imagegen/transfer/transfer.go:172`) extracts realm/service/scope from `WWW-Authenticate` headers with no validation. The realm value is then passed to the `GetToken` callback.

In `server/images.go:755-761`, the `GetToken` callback calls `getAuthorizationToken(ctx, registryChallenge{Realm: challenge.Realm, ...}, base.Host)`. The `base.Host` is the original registry host. The check in `server/auth.go`'s `getAuthorizationToken` verifies `realm.Host == originalHost`.

**Actual exposure**: The realm-host check IS present via the callback. However, the `downloader.resolve()` function at `transfer/download.go:350` calls `d.getToken` on 401 responses during the URL resolution phase. At this point, `d.baseURL` may have been overridden by earlier redirects to a CDN URL. If a CDN 401 response provides a crafted `WWW-Authenticate` realm pointing to `attacker.com`, the `base.Host` in the callback was set at `pullWithTransfer` call time to the ORIGINAL registry host. So the check `challenge.Realm host == base.Host` would correctly reject attacker.com.

**Finding**: The server-side protection via callback IS sound for this specific path. However, there is a subtler gap: `transfer/transfer.go:parseAuthChallenge` does NOT validate that the realm uses `https://`. A `realm="http://attacker.com/token"` value passes through. The `getAuthorizationToken` in `server/auth.go` makes an outbound HTTP request to the realm URL; if `http://` is passed and the realm-host matches the original registry host (e.g., `realm="http://registry.ollama.ai/token"` — same host, downgraded to HTTP), the ed25519-signed token is sent over plaintext to an attacker who can MITM.

**Attack**: Control a redirect path → craft 401 with `WWW-Authenticate: Bearer realm="http://registry.ollama.ai/token"` → realm host matches original → token sent via HTTP → MITM reads the signed token.

**VALIDATED**: `transfer/transfer.go:172-210` parses realm without scheme check. `server/auth.go:53-90` does not check that `realmURL.Scheme == "https"` before making the request.

**Severity**: HIGH — ed25519-signed auth token sent over HTTP (MITM-readable) when registry downgrades scheme in realm URL; requires MITM position on non-TLS network.

---

## PH-10: Contradiction in "size field bounds transfer" assumption — negative/zero blob.Size bypasses write constraints (MEDIUM)

**Stated protection assumption**: `blob.Size` in `transfer.Blob` is used to bound writes and detect mismatches; the transfer package correctly handles all values.

**Contradiction**: `transfer/download.go:171-180`:
```go
if blob.Size >= resumeThreshold {
    if fi, statErr := os.Stat(tmp); statErr == nil {
        if fi.Size() < blob.Size {
            existingSize = fi.Size()
        } else if fi.Size() > blob.Size {
            os.Remove(tmp)
        }
    }
}
```
If `blob.Size == 0`: `fi.Size() < 0` is false for any real file, `fi.Size() > 0` is true, so `os.Remove(tmp)` is always called. BUT `os.Create(tmp)` at line 242 still runs, creating an empty file. The empty file then passes `sha256` check (sha256 of empty = a known constant). If the attacker sets `digest = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"` (sha256 of empty string), then `got == blob.Digest`, and `os.Rename(tmp, dest)` runs — writing an empty file to an attacker-chosen `dest`.

If `blob.Size` is negative (int64 < 0): `blob.Size >= resumeThreshold (64MB)` is false, so no resume logic; `os.Create(tmp)` runs; reading 0 bytes (`io.CopyN` with a negative limit panics or returns 0 bytes); `sha256("")` matches the empty-string digest. Potential: create an empty file at a traversal path.

**VALIDATED**: Confirmed that `blob.Size` comes from `layer.Size` (int64 from manifest JSON); no lower bound check. The sha256 of the empty string is well-known. With `Size=0` and `Digest="sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"`, the save function creates and renames an empty file at the target path. Combined with digest traversal, this creates an empty file at any writable path.

**Severity**: MEDIUM — empty file creation at attacker-chosen path; lower impact than arbitrary-content write (PH-01) but simpler to trigger (no size threshold concern).

---

## PH-11: Contradiction in "decodeUserJSON prevents invalid input" — no body size limit in handlePull (MEDIUM)

**Stated protection assumption**: `decodeUserJSON` properly handles malformed JSON and returns a 400.

**Contradiction**: `decodeUserJSON` at `server/internal/registry/server.go:377` calls `json.NewDecoder(r.Body).Decode(&v)`. There is NO `http.MaxBytesReader` wrapping `r.Body`. An attacker sending a multi-GB JSON body to `/api/pull` (when `OLLAMA_EXPERIMENT=client2` is active, bypassing gin middleware) will exhaust memory in the JSON decoder before any size limit fires.

Note: even without `client2`, `gin.ShouldBindJSON` in the standard path also lacks a size cap at the handler level (though gin's default may impose one — but this needs verification).

**VALIDATED**: `server/internal/registry/server.go:264`: `p, err := decodeUserJSON[*params](r.Body)` — no MaxBytesReader wrapping. The `client2` path explicitly bypasses the gin middleware chain that might add a size limit.

**Severity**: MEDIUM — DoS via oversized JSON body on the client2 path; gin path may or may not have a default limit.

---

## PH-12: Contradiction in "Insecure flag controls HTTP permission" — redirect target scheme not re-validated (HIGH)

**Stated protection assumption**: The `Insecure` flag gatekeeps HTTP access; when `Insecure=false` (default), only HTTPS connections are made to registries.

**Contradiction**: `blobDownload.run()` at `server/download.go:229-270` performs a GET to `requestURL` with a redirect callback that stops at the first off-host redirect and returns `resp.Location()` as `directURL`. The `directURL` is used for ALL subsequent part downloads WITHOUT re-checking its scheme.

If the registry redirects the initial GET (for the blob URL) to `http://cdn.attacker.com/blob`, `directURL` will be `http://cdn.attacker.com/blob`. All 16 parallel download goroutines then fetch from this HTTP URL. The `Insecure` flag was checked in `makeRequest` for the registry connection but is NOT re-applied to `directURL`.

Moreover, at `server/download.go:240-252`, the redirect check function returns `http.ErrUseLastResponse` for off-host redirects. The CALLING code then calls `resp.Location()` and uses that URL as `directURL`. `resp.Location()` returns the URL from the `Location` header — which can be HTTP even when the original request was HTTPS.

**Attack**: Control the registry (or MITM the registry connection pre-TLS termination) to return `Location: http://attacker.com/blob` in the redirect. All blob bytes come from an HTTP connection. MITM can substitute arbitrary content. The streaming hash will catch this ONLY if the final bytes don't match the expected digest — but for a model being served for the first time (no prior verified copy), the hash is the only check.

**VALIDATED**: `server/download.go:265-269`:
```go
return resp.Location()  // can be http://
```
Used at `download.go:271`: if `err != nil { return nil, err }` — no scheme check on the returned URL. Line `download.go:286`: `g.Go(func() error { ... w := io.NewOffsetWriter(file, part.StartsAt()); err = b.downloadChunk(inner, directURL, w, part)` — `directURL` is used without re-checking scheme.

**Severity**: HIGH — HTTPS-to-HTTP downgrade on CDN redirect allows MITM of blob content; streaming hash provides only partial protection (catches wrong content, but attacker who can deliver bytes that hash to the expected digest has full control — this is only feasible with a hash collision, so primary impact is MITM content injection that gets caught at hash check, resulting in denial-of-service rather than silent compromise).

---

## PH-13: Contradiction in "manifest.BlobsPath covers all digest-to-path conversions" assumption — x/imagegen/manifest/manifest.go BlobPath (HIGH)

**Stated protection assumption**: After the CVE-2024-37032 fix, all digest-to-path conversions are validated.

**Contradiction**: `x/imagegen/manifest/manifest.go` (not part of the Group A files but invoked transitively) and `x/create/create.go` both use a `BlobPath(digest)` helper that does raw `strings.Replace(digest, ":", "-", 1)` — the same unvalidated pattern. These are referenced in `x/mlxrunner` and imagegen paths.

More directly within Group A: the upload path reads a file via `os.Open(filepath.Join(u.srcDir, digestToPath(blob.Digest)))` — if a manifest was written by the imagegen path (which uses the unvalidated `BlobPath`), the digest in that manifest could contain traversal components, and the upload then reads the wrong file.

**VALIDATED (partial)**: `x/imagegen/transfer/upload.go:181` confirmed. The source digest comes from `layer.Digest` in the manifest passed to `pushWithTransfer`. If that manifest was generated by the imagegen path using the unvalidated `BlobPath`, a traversal digest could propagate.

**Severity**: HIGH — read of arbitrary file via upload when manifest contains traversal digest; lower exploitability than PH-01 as it requires manifest contamination.

---

## PH-14: Contradiction in "getAuthorizationToken body is bounded" — token response OOM DoS (HIGH)

**Stated protection assumption**: Auth tokens from registry are small JSON blobs; no DoS risk.

**Contradiction**: `server/auth.go:81` (DFD-13 from KB): `io.ReadAll(response.Body)` with no size cap. `getAuthorizationToken` is called on every auth challenge — which occurs during `makeRequestWithRetry` whenever the registry returns 401. An attacker-controlled registry can serve a 2GB response body to this endpoint, causing OOM before the JSON unmarshal even begins. This is particularly effective because the auth token fetch happens BEFORE any model content is transferred, so a single unauthenticated `POST /api/pull` can trigger the OOM.

**VALIDATED**: `server/auth.go:81` confirmed no `io.LimitReader`. `makeRequestWithRetry` at `images.go:888-933` calls `getAuthorizationToken` on 401. The attacker-controlled registry returns 401 immediately with a crafted `WWW-Authenticate` header pointing to a large-response token endpoint.

**Severity**: HIGH — one-request OOM DoS; works from localhost/DNS-rebind on default non-authenticated Ollama instance.
