Cold adversarial review of `archon/findings-draft/p8-006-imagegen-blobpath-traversal.md`.

Verdict: DISPROVED
Severity-Final: LOW (downgraded from HIGH)
PoC-Status: blocked (reproduction attempted; digest verification rejects the input)

## Step 1 — Restate

The finding claims that `x/imagegen/manifest.ModelManifest.BlobPath(digest)` builds on-disk blob paths from a raw `strings.Replace(digest, ":", "-", 1)` with no traversal guard. Callers `ReadConfig`, `OpenBlob`, and `detectQuantizationFromBlobs` subsequently `os.Open`/`os.ReadFile` that path. Combined with an attacker-controlled manifest whose layer digest contains `../` sequences, the finding argues arbitrary-file-read by the ollama process.

Sub-claims:
- A: Attacker can cause a manifest with a digest like `sha256:../../../etc/passwd` to be stored at `$OLLAMA_MODELS/manifests/...` via either a malicious registry pull or direct filesystem write.
- B: Callers of `BlobPath` never validate the digest, so a path like `$OLLAMA_MODELS/blobs/sha256-../../../etc/passwd` is produced and then consumed by `os.ReadFile`/`os.Open`.
- C: The read succeeds and yields arbitrary file contents to the ollama process.

Sub-claim B and C are code-level true. Sub-claim A is the gated step.

## Step 2 — Independent Code Path Trace

Source -> sink trace, starting from attacker-controllable input:

1. `server/images.go:621` `pullModelManifest` reads manifest bytes from the attacker registry via `io.ReadAll`. No digest-format validation on layers.
2. Two dispatch paths:
   - `hasTensorLayers(layers)` true: `server/images.go:634` calls `pullWithTransfer`.
   - Otherwise: `server/images.go:642` loops over each layer calling `downloadBlob`.
3. `pullWithTransfer` (`server/images.go:721-793`) builds `[]transfer.Blob` with `Digest: layer.Digest` verbatim (no validation), then calls `transfer.Download`.
4. `transfer.Download` -> `downloader.save` (`x/imagegen/transfer/download.go:212-266`). Line 213 computes `dest := filepath.Join(d.destDir, digestToPath(blob.Digest))`. `digestToPath` (line 164-170) only does a positional `sha256:` -> `sha256-` swap; no traversal guard. `os.MkdirAll(filepath.Dir(dest), 0o755)` would create the traversal directory. Stream is copied into `dest+".tmp"` while sha256 is accumulated.
5. Line 257 `if got := fmt.Sprintf("sha256:%x", h.Sum(nil)); got != blob.Digest { os.Remove(tmp); return ... "digest mismatch" }`. Because `sha256.Sum256` output is always 64 hex chars from `[0-9a-f]`, `got` can never equal a string containing `.` or `/`. The comparison deterministically fails.
6. On mismatch, the `.tmp` file is removed and the error bubbles up, so `pullWithTransfer` returns before reaching line 787 `os.WriteFile(fp, manifestData, 0o644)`. The manifest file is never persisted.
7. Non-transfer path `downloadBlob` (`server/download.go:468`) calls `manifest.BlobsPath(opts.digest)` at line 473. `manifest/paths.go:40-46` applies `^sha256[:-][0-9a-fA-F]{64}$` regex and returns `ErrInvalidDigestFormat` for anything else. Again, `pull` fails before `os.WriteFile` at `server/images.go:690`.

Sinks (if a traversal digest ever did reach them):
- `x/imagegen/manifest/manifest.go:101-105 BlobPath`: `filepath.Join(m.BlobDir, strings.Replace(digest, ":", "-", 1))`. No validation. `filepath.Join("/root/blobs", "sha256-../../../etc/passwd")` collapses to `/root/etc/passwd`.
- `ReadConfig` line 141-142: `os.ReadFile(m.BlobPath(layer.Digest))`.
- `OpenBlob` line 155-156: `os.Open(m.BlobPath(digest))`.
- `detectQuantizationFromBlobs` line 240: `readBlobHeader(manifest.BlobPath(layer.Digest))`.

The sinks are real and unguarded. Reachability is the issue.

## Step 3 — Protection Surface Search

| Layer | Protection | Blocks the claimed chain? |
|-------|------------|---------------------------|
| Framework | `x/imagegen/transfer/download.go:257` SHA256 content-vs-digest check | YES — deterministic string-equality failure for any digest containing non-hex chars or wrong length |
| Framework | `manifest.BlobsPath` regex `^sha256[:-][0-9a-fA-F]{64}$` (`manifest/paths.go:40`) | YES — used on the non-transfer pull path via `downloadBlob` and on `verifyBlob`/`deleteUnusedLayers` |
| Application | `pullWithTransfer` error-returns on `transfer.Download` failure before writing manifest (`server/images.go:772-787`) | YES — keeps the disk in a clean state |
| Application | `manifest.NewLayer` used in `x/create/client/create.go:208` computes digests from content | YES — local create path cannot produce a traversal digest |
| Data | Only two manifest-write sites: `server/images.go:690` and `:787` | Both gated above |

No additional configuration, WAF, or middleware is needed; the pull pipeline's native digest verification is fatal to the attack.

## Step 4 — Real-Environment Reproduction

Environment: local `go run` against the actual `x/imagegen/transfer` package at HEAD 57653b8e.
Healthcheck: `go version` -> `go1.26.1 darwin/arm64`; module compiles.

Attempt 1: Stood up an `httptest.NewServer` registry that returns arbitrary bytes for any `/v2/library/evil/blobs/*` request. Invoked `transfer.Download` with `Blob{Digest: "sha256:../../../etc/passwd", Size: 35}` and a non-zero body. Observed server receive requests for `/v2/library/evil/blobs/sha256:../../../etc/passwd` twelve times (retry loop) and then:

```
download returned error: max retries exceeded: digest mismatch
sha256(content) = sha256:7c5a3bceb50928dbbccade69c7ef3bd1bc57dd710711f770c5eff762859ace79
expected (traversal) = sha256:../../../etc/passwd
```

No file persisted. Evidence: `archon/real-env-evidence/imagegen-blobpath-traversal/attempt1.txt` and `repro.go`.

Because the first attempt already demonstrates the blocking protection is deterministic and string-level, no further variations are needed.

## Step 5 — Prosecution and Defense Briefs

### Prosecution

`x/imagegen/manifest/manifest.go:101-105` BlobPath is demonstrably unsafe: `filepath.Join("/blobs", "sha256-../../../etc/passwd")` resolves to `/etc/passwd`. `ReadConfig`, `OpenBlob`, and `detectQuantizationFromBlobs` read whatever file that path points to. The imagegen manifest package has no internal validation, and no caller in `x/mlxrunner/model/root.go:48`, `x/imagegen/models/zimage/zimage.go:59`, or `x/imagegen/memory.go:46` sanitizes the digest before reaching the helpers. The underlying flaw matches the CVE-2024-37032 class.

### Defense

The claimed attack vector is a malicious registry manifest with traversal digest reaching `BlobPath`. Two independent controls make this impossible on HEAD:

1. `x/imagegen/transfer/download.go:257` computes SHA256 of the downloaded blob content and fails the transfer unless the string `fmt.Sprintf("sha256:%x", ...)` equals `blob.Digest` verbatim. Since hex output cannot contain `/` or `.`, a traversal digest can never be accepted.
2. `manifest/paths.go:40-46` regex `^sha256[:-][0-9a-fA-F]{64}$` rejects malformed digests on the legacy download path.

`pullWithTransfer` only reaches `os.WriteFile(manifestData)` at line 787 after the entire download succeeds; any blob-level rejection returns at line 773 and no manifest is persisted. `CreateImageGenModel` and its siblings derive digests via `manifest.NewLayer(r, ...)` which applies `sha256.Sum256` to content, so locally created manifests cannot carry traversal digests either.

The only remaining vector listed in the finding — "local attacker with manifest-dir write access" — is a post-compromise condition. An actor who can already write to `$OLLAMA_MODELS/manifests/...` has filesystem-level access and does not need this bug to read `/etc/passwd`.

Reproduction against the real transfer package at HEAD 57653b8e failed with `max retries exceeded: digest mismatch` and produced no disk artifacts.

## Step 6 — Severity Challenge

Starting at MEDIUM. The code-level gap is real (defense-in-depth issue) but remote exploitation is blocked by a deterministic content-hash check that cannot be bypassed with any attacker-controlled input. The only reachable exploitation requires pre-existing filesystem write, which is strictly stronger than the claimed impact (arbitrary file read). Downgraded to LOW.

## Step 7 — Verdict

DISPROVED. The defense brief identifies two independent protections (SHA256 content-vs-digest check and `BlobsPath` regex) that block the entire claimed chain, and real-environment reproduction confirmed the transfer pipeline rejects a traversal digest with "digest mismatch" and writes nothing. The underlying `BlobPath` implementation is still unsafe as a defense-in-depth matter, but it is not currently reachable from an attacker-controlled manifest.
