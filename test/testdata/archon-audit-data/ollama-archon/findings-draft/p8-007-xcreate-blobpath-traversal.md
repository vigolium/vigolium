Phase: 8
Sequence: 007
Slug: xcreate-blobpath-traversal
Verdict: FALSE POSITIVE (adversarial)
Rationale: x/create/create.go:102 and :158 use strings.Replace(digest, ":", "-", 1) + filepath.Join + os.ReadFile with no IsLocal; reachable via IsSafetensorsModel / IsImageGenModel / GetModelArchitecture dispatch — Advocate found no caller or internal validation.
Severity-Original: HIGH
Adversarial-Verdict: DISPROVED
Adversarial-Rationale: The four helpers that would reach the unsafe sinks (IsSafetensorsModel, IsSafetensorsLLMModel, IsImageGenModel, GetModelArchitecture) have zero call sites in the entire repository outside of create.go itself — cmd/, server/, and x/create/client/ do not invoke them, so the "dispatch path" described in the finding does not exist and the traversal cannot be reached by any attacker input.
Severity-Final: LOW
PoC-Status: blocked
Pre-FP-Flag: none
Debate: archon/chamber-workspace/chamber-01/debate.md

## Summary

`x/create/create.go` contains two near-identical uses of the raw `strings.Replace(digest, ":", "-", 1)` pattern — at `loadModelConfig` (line 102-105) and `GetModelArchitecture` (line 157-163). Both read files from `filepath.Join(defaultBlobDir(), blobName)` via `os.ReadFile(blobPath)` without calling `manifest.BlobsPath` and without `filepath.IsLocal` / regex.

These helpers are reached from the dispatch path: `IsSafetensorsModel`, `IsSafetensorsLLMModel`, `IsImageGenModel`, `GetModelArchitecture` — all used during model-type decisions in the routing layer. A manifest with traversal `Config.Digest` causes arbitrary-file read during dispatch.

## Location

- `x/create/create.go:95-116` — `loadModelConfig` (Config.Digest sink)
- `x/create/create.go:148-175` — `GetModelArchitecture` (layer.Digest sink, scoped to layers named `config.json` with JSON mediatype)
- Callers: `IsSafetensorsModel` (line 120), `IsSafetensorsLLMModel` (line 130), `IsImageGenModel` (line 140), `GetModelArchitecture` (line 149)

## Attacker Control

Same as Finding 006 — attacker persuades victim to pull a manifest with traversal digest; subsequent dispatch invokes these helpers.

## Trust Boundary Crossed

Network-pulled manifest → local filesystem reads.

## Impact

Arbitrary file read as ollama user. Triggered automatically during model-type dispatch (no explicit user action needed beyond an initial interaction with the model). JSON-parse failures may reflect content in error responses.

## Evidence

```go
// x/create/create.go:95-116
func loadModelConfig(modelName string) (*ModelConfig, error) {
    manifest, err := loadManifest(modelName)
    ...
    // Read the config blob
    blobName := strings.Replace(manifest.Config.Digest, ":", "-", 1)   // <-- unvalidated
    blobPath := filepath.Join(defaultBlobDir(), blobName)

    data, err := os.ReadFile(blobPath)   // <-- sink
    ...
    var config ModelConfig
    if err := json.Unmarshal(data, &config); err != nil {
        return nil, err
    }
    return &config, nil
}

// x/create/create.go:148-175
func GetModelArchitecture(modelName string) (string, error) {
    manifest, err := loadManifest(modelName)
    ...
    for _, layer := range manifest.Layers {
        if layer.Name == "config.json" && layer.MediaType == "application/vnd.ollama.image.json" {
            blobName := strings.Replace(layer.Digest, ":", "-", 1)   // <-- unvalidated
            blobPath := filepath.Join(defaultBlobDir(), blobName)

            data, err := os.ReadFile(blobPath)   // <-- sink
            ...
        }
    }
    ...
}
```

## Reproduction Steps

1. Stage a manifest whose `config` layer has `Digest: "sha256:../../../etc/passwd"`.
2. Invoke any dispatch path that calls `IsSafetensorsModel(modelName)` or `GetModelArchitecture(modelName)` — common during `ollama run`, `ollama show`, or template-aware endpoints.
3. `/etc/passwd` is read; `json.Unmarshal` error message or dispatch result reflects content.

Debate context: Tracer confirmed both sinks on HEAD. Advocate confirmed no validation. Fix: replace both `strings.Replace` calls with `manifest.BlobsPath(digest)` and propagate the error.
