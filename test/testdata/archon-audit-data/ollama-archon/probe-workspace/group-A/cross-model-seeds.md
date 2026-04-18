# Cross-Model Seeds — Group A

## CROSS-01: PH-01 (digest path traversal) + PH-08 (push reads traversal digest) → arbitrary file read via push

Source-A: PH-01 from backward-reasoner (round-1-hypotheses.md) — `pullWithTransfer` writes attacker-chosen file via traversal digest
Source-B: PH-08 from contradiction-reasoner (round-2-hypotheses.md) — `pushWithTransfer` reads via `digestToPath(blob.Digest)` without BlobsPath validation

Connection: Both involve the same `digestToPath` function in `x/imagegen/transfer/`. PH-01 establishes that a pull from a malicious registry can write a crafted manifest to `$OLLAMA_MODELS/manifests/`. PH-08 establishes that a subsequent push reads blob files using unvalidated digests from that manifest. The combined chain is: (1) pull a malicious model that writes a traversal manifest entry, (2) push that model — triggering `os.Open(filepath.Join(srcDir, "sha256-../../../etc/shadow"))` — the contents of `/etc/shadow` are then uploaded to the attacker's registry.

Combined hypothesis: A two-step pull-then-push sequence from an attacker-controlled registry achieves arbitrary file read and exfiltration. The pull step writes a manifest with traversal digests. The push step reads from those traversal paths and sends the contents to the registry.

Test direction for causal-verifier: Confirm that `pushWithTransfer` at `images.go:795-851` copies `layer.Digest` directly into `blobs[i].Digest` without `BlobsPath` validation; then confirm `upload.go:181` calls `os.Open(filepath.Join(srcDir, digestToPath(digest)))`. Trace whether any manifest sanitization happens between pull and push.

---

## CROSS-02: PH-01 (size >= 64MB .tmp persists) + PH-10 (size=0 + empty hash → empty file) → two complementary write primitives

Source-A: PH-01 — `.tmp` persists for `blob.Size >= 64MB`; hash mismatch on traversal digest means `.tmp` stays with attacker bytes
Source-B: PH-10 — `blob.Size=0` + sha256-of-empty-string digest creates an empty file at any path (simpler variant, no size threshold)

Connection: Both operate on the same `downloader.save` function (`x/imagegen/transfer/download.go:212`). PH-01 requires blob.Size >= 64MB and accepts partial content. PH-10 works with any size=0 layer. Together they provide two write-primitive variants with different requirements and slightly different file-content properties.

Combined hypothesis: An attacker manifest can include BOTH types of layers: a large traversal-digest layer (size >= 64MB) for arbitrary-content write via persistent .tmp, AND a zero-size traversal-digest layer with the empty-string sha256 for clean empty-file creation at a different target path. The empty-file creation is simpler and more reliable; the partial-file write requires a size-threshold but achieves content injection.

Test direction for causal-verifier: Confirm `transfer/download.go:257-265`: verify `got != blob.Digest` for the empty-string case produces `os.Remove(tmp)` (PH-10 requires hash to MATCH, not mismatch). Re-examine: if `digest == "sha256:e3b0..."` (sha256 of empty), and 0 bytes are written, then `got == blob.Digest` → `os.Rename(tmp, dest)` RUNS. This IS a valid empty-file write. Also confirm that with `size=0`, `blob.Size < resumeThreshold` → `os.Remove(dest+".tmp")` cleanup runs on failure — but if hash MATCHES, it goes to the rename branch first.

---

## CROSS-03: PH-03 (SSRF via pull host) + PH-04 (manifest io.ReadAll OOM) → SSRF-amplified OOM

Source-A: PH-03 — arbitrary host in pull request enables SSRF
Source-B: PH-04 — `pullModelManifest` io.ReadAll with no LimitReader

Connection: Both operate on `pullModelManifest` (`server/images.go:853-875`). PH-03 establishes that the registry host is attacker-controlled. PH-04 establishes that the response body from that registry is unconditionally `io.ReadAll`-ed. Together: ANY reachable internal HTTP endpoint that returns a large body causes OOM when used as the registry host.

Combined hypothesis: An attacker with access to Ollama's API (via DNS rebind or localhost) can cause OOM by directing a pull at any internal endpoint (IMDS, internal proxy, co-located service) that returns a large response body. The SSRF and OOM DoS are simultaneous: the SSRF happens AND the large response OOMs the server.

Test direction for causal-verifier: Confirm `pullModelManifest` line 864 has no limit. Verify the flow from `PullHandler` → `parseNormalizePullModelRef` → `PullModel` → `pullModelManifest` — does `parseNormalizePullModelRef` restrict the registry host? Check `server/model_resolver.go:parseNormalizePullModelRef`.

---

## CROSS-04: PH-04 (io.ReadAll on manifest) + PH-14 (io.ReadAll on auth token) → double OOM via single pull request

Source-A: PH-04 — manifest response io.ReadAll, no LimitReader
Source-B: PH-14 — token response io.ReadAll in getAuthorizationToken, no LimitReader

Connection: Both are triggered from a single `POST /api/pull` request. The auth token fetch (PH-14) happens FIRST (before manifest fetch) when the registry returns 401. The manifest fetch (PH-04) happens AFTER auth succeeds. An attacker registry can trigger BOTH: return 401 with large token response (PH-14 OOM), OR if the client survives that, return 200 with large manifest body (PH-04 OOM).

Combined hypothesis: The auth challenge happens at `makeRequestWithRetry` line 906, before `pullModelManifest` returns. A registry that returns 401 with `io.ReadAll` in the token endpoint triggers OOM at auth time, not manifest time. The two `io.ReadAll` calls are sequential barriers — either one can OOM the server independently, making the DoS more reliable.

Test direction for causal-verifier: Trace the call sequence in `makeRequestWithRetry` (images.go:890-933): does the 401 path → `getAuthorizationToken` → token endpoint `io.ReadAll` happen within `pullModelManifest`? Yes — `pullModelManifest` calls `makeRequestWithRetry`, which on 401 calls `getAuthorizationToken`. So one request has two sequential `io.ReadAll` opportunities.

---

## CROSS-05: PH-12 (HTTPS-to-HTTP redirect on CDN) + PH-05 (Content-Range not validated) → MITM byte injection that beats per-part hash then hits full-hash verification

Source-A: PH-12 — registry redirects blob download to HTTP CDN; MITM can inject arbitrary bytes
Source-B: PH-05 — Content-Range not validated; MITM can return 200 instead of 206 filling first bytes into all part slots

Connection: Both operate in `blobDownload.run()` and `blobDownload.downloadChunk`. PH-12 establishes that the download can be downgraded to HTTP via redirect. PH-05 establishes that on HTTP, a MITM can send a 200 response (full blob) to every part's request, writing the first N bytes of the blob into each part's slot. Combined: an HTTP MITM can write specific byte patterns into specific offsets of the partial file.

Combined hypothesis: On an HTTP CDN redirect (PH-12), a MITM sends 200 responses to all part requests. Each response contains the first `partSize` bytes of the blob. The first part's slot gets the correct content (bytes 0..partSize-1 of the real blob). All subsequent parts get those same bytes written at their offsets. The final file contains the real first `partSize` bytes at offset 0, and copies of those same bytes at each subsequent part offset. The streaming hash will NOT match the expected digest, returning a hash mismatch error. The partial file persists (Finding 4 / Finding 7 from KB). Net effect: stuck download (DoS); combining with PH-06 race may achieve silent corruption.

Test direction for causal-verifier: Confirm that `downloadChunk` at `server/download.go:338` sends the Range header but at line 345 `io.CopyN` reads `part.Size - part.Completed.Load()` bytes regardless of status code. Check: if status is 200 and body is large, does CopyN correctly terminate? Yes it terminates at part.Size bytes. So the net effect is: part 0 gets correct bytes (0..partSize), parts 1..N get wrong bytes (bytes 0..partSize repeated). The file is corrupt. Hash check fires. Partial file persists.
