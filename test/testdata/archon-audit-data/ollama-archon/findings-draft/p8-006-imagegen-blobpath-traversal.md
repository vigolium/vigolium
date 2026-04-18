Phase: 8
Sequence: 006
Slug: imagegen-blobpath-traversal
Verdict: FALSE POSITIVE (adversarial)
Rationale: x/imagegen/manifest/manifest.go:101 BlobPath uses strings.Replace without regex or IsLocal; callers ReadConfig, OpenBlob, detectQuantizationFromBlobs are arbitrary-file-read sinks; Advocate found no caller-level validation.
Severity-Original: HIGH
PoC-Status: blocked
Pre-FP-Flag: none
Debate: archon/chamber-workspace/chamber-01/debate.md
Adversarial-Verdict: DISPROVED
Adversarial-Rationale: The only production manifest-write sites (server/images.go:690, :787) are gated on either manifest.BlobsPath regex (non-transfer path) or full SHA256 digest-vs-content verification in x/imagegen/transfer/download.go:257 (transfer path). Because sha256 output is always [0-9a-f]{64}, a traversal digest like "sha256:../../../etc/passwd" can never match any downloaded content, so a malicious-registry pull fails with "digest mismatch" before the manifest is ever persisted, meaning no caller of x/imagegen/manifest.BlobPath ever sees a traversal digest on disk. Real-env reproduction at commit 57653b8e against transfer.Download produced `max retries exceeded: digest mismatch` and wrote nothing.
Severity-Final: LOW
PoC-Status: blocked

## Summary

`x/imagegen/manifest.ModelManifest.BlobPath(digest)` at `manifest.go:101-105` computes a blob filesystem path from a layer digest using a raw `strings.Replace(digest, ":", "-", 1)` — the same class of bug as Findings 001 and 004, now on the read side of the imagegen subsystem. Read sinks include `ReadConfig` (line 141), `OpenBlob` (line 156), and `detectQuantizationFromBlobs` via `readBlobHeader(manifest.BlobPath(layer.Digest))` (line 240). Callers of these helpers include the imagegen dispatcher and mlxrunner model loading.

An attacker-controlled manifest with `"digest":"sha256:../../../etc/passwd"` causes any subsequent call into these helpers to read the target file and either:
- `ReadConfig` — unmarshals into the caller's config struct (if JSON, surfaced in `/api/show`-like endpoints)
- `OpenBlob` — returns an `io.ReadSeekCloser` from which the caller copies bytes into downstream processing (GGUF parser, tensor decoder), potentially leading to out-of-spec parsing + information disclosure
- `detectQuantizationFromBlobs` — reads first 1 MB header, branch decisions reflect contents

## Location

- `x/imagegen/manifest/manifest.go:100-105` — `BlobPath`
- `x/imagegen/manifest/manifest.go:141` — `ReadConfig` sink
- `x/imagegen/manifest/manifest.go:156` — `OpenBlob` sink (`return os.Open(m.BlobPath(digest))`)
- `x/imagegen/manifest/manifest.go:240` — `detectQuantizationFromBlobs` sink
- Callers: `x/mlxrunner/model/root.go:48` (loads model config during inference startup), imagegen dispatcher via `x/create/create.go` `IsImageGenModel` etc.

## Attacker Control

Any actor who can get a manifest with traversal digest onto disk. Delivery vectors:
1. Pull from malicious registry (stored verbatim by `pullWithTransfer` at `images.go:787`).
2. Local attacker with manifest-dir write access.

## Trust Boundary Crossed

Network-pulled manifest → local filesystem reads at arbitrary paths.

## Impact

- Arbitrary file read by the ollama user across the entire filesystem.
- Information disclosure through error-message reflection or through the model's subsequent use (e.g., the loaded "config" drives dispatch decisions).
- Combined with Finding 007 (`x/create` variant), every major "what kind of model is this?" helper is a file-read primitive.

## Evidence

```go
// x/imagegen/manifest/manifest.go:100-105
// BlobPath returns the full path to a blob given its digest.
func (m *ModelManifest) BlobPath(digest string) string {
    // Convert "sha256:abc123" to "sha256-abc123"
    blobName := strings.Replace(digest, ":", "-", 1)   // <-- unvalidated
    return filepath.Join(m.BlobDir, blobName)
}

// line 134-141 (ReadConfig)
func (m *ModelManifest) ReadConfig(configPath string) ([]byte, error) {
    layer := m.GetConfigLayer(configPath)
    ...
    blobPath := m.BlobPath(layer.Digest)
    return os.ReadFile(blobPath)
}

// line 154-156 (OpenBlob)
func (m *ModelManifest) OpenBlob(digest string) (io.ReadSeekCloser, error) {
    ...
    return os.Open(m.BlobPath(digest))
}

// line 237-242 (detectQuantizationFromBlobs)
for _, layer := range manifest.Manifest.Layers {
    if layer.MediaType == "application/vnd.ollama.image.tensor" {
        data, err := readBlobHeader(manifest.BlobPath(layer.Digest))
        ...
    }
}
```

Additionally, `resolveManifestPath` (`manifest.go:70-98`) splits the model name on `/` and `:` and feeds components directly to `filepath.Join(DefaultManifestDir(), host, namespace, name, tag)` — a separate traversal primitive via the model name (`name = "../../etc/passwd"` partially absorbs but with deep nesting can escape).

## Reproduction Steps

1. Stand up attacker registry and have victim pull:
   ```
   ollama pull evil.com/img:latest
   ```
   with manifest containing `{"mediaType":"application/vnd.ollama.image.json","digest":"sha256:../../../etc/passwd","size":1024,"name":"config.json"}`.
2. Victim invokes imagegen dispatch (e.g., `ollama run evil.com/img`) — `IsImageGenModel` → `loadModelConfig` → `manifest.ReadConfig("config.json")` → `BlobPath("sha256:../../../etc/passwd")` → `/etc/passwd` read as bytes → JSON-unmarshaled into `ModelConfig`; unmarshal error likely surfaces the file contents in the API response error.

Debate context: Tracer confirmed three sinks. Advocate verified no caller validates the digest and that `BlobPath` itself has no check. This is independent of Finding 007 but shares root cause — it's a new sink in a different package.
