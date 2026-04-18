Phase: 10
Sequence: 000
Slug: imagegen-safetensors-uint64-oom
Verdict: VALID
Rationale: x/imagegen/safetensors/safetensors.go parseSafetensorHeader reads uint64 headerSize and calls make([]byte, headerSize) with no cap, enabling OOM on the image-generation model creation path.
Severity-Original: HIGH
Severity-Final: HIGH
PoC-Status: pending
Origin-Finding: archon/findings-draft/p8-024-safetensors-header-int64-oom.md
Origin-Pattern: AP-024

## Summary

`x/imagegen/safetensors/safetensors.go:33-40` (`parseSafetensorHeader`) reads an 8-byte little-endian `uint64` headerSize from an attacker-controlled safetensors file and calls `make([]byte, headerSize)` with no bounds check. This is the image-generation subsystem's own copy of the parser — a distinct code path from both the original finding (`convert/reader_safetensors.go`) and variant p10-024-a (`x/safetensors/extractor.go`). All three copies share the same root cause.

## Location

`x/imagegen/safetensors/safetensors.go:33-40` function `parseSafetensorHeader`

```go
var headerSize uint64
if err := binary.Read(f, binary.LittleEndian, &headerSize); err != nil {
    return nil, fmt.Errorf("failed to read header size: %w", err)
}

headerBytes := make([]byte, headerSize)   // <-- uncapped allocation
if _, err := f.Read(headerBytes); err != nil {
    return nil, fmt.Errorf("failed to read header: %w", err)
}
```

## Attacker Control

`parseSafetensorHeader` is called from:
- `x/imagegen/safetensors/safetensors.go:100` — `LoadModelWeights` iterates `os.ReadDir(dir)` and opens every `.safetensors` file.
- `x/imagegen/safetensors/safetensors.go:129` — `LoadModelWeightsFromPaths` processes a list of blob paths from a manifest.

These functions are reached during image-generation model loading when a user submits or imports an imagegen model referencing a directory or manifest containing a crafted `.safetensors` file.

## Trust Boundary Crossed

HTTP API / local filesystem -> process heap -> kernel OOM-killer.

## Impact

Instant unrecoverable OOM or runtime panic. Crashes the `ollama serve` process for all concurrent users. The image-generation path is a newer subsystem and has no separate process isolation.

## Evidence

```
// x/imagegen/safetensors/safetensors.go:26-49
func parseSafetensorHeader(path string) (SafetensorHeader, error) {
    f, err := os.Open(path)
    ...
    var headerSize uint64
    if err := binary.Read(f, binary.LittleEndian, &headerSize); err != nil {
        return nil, fmt.Errorf("failed to read header size: %w", err)
    }

    headerBytes := make([]byte, headerSize)  // NO CAP
    if _, err := f.Read(headerBytes); err != nil {
        return nil, fmt.Errorf("failed to read header: %w", err)
    }
    ...
}
```

Called at:
- `safetensors.go:100`: `header, err := parseSafetensorHeader(path)` inside `LoadModelWeights` directory scan.
- `safetensors.go:129`: `header, err := parseSafetensorHeader(path)` inside `LoadModelWeightsFromPaths`.

## Reproduction Steps

1. Craft `evil.safetensors` with first 8 bytes `\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF`.
2. Place it in a directory used as an image-generation model source.
3. Trigger image-generation model loading via the relevant API endpoint.
4. Process crashes with OOM — no recovery possible.

Fix direction: same as p10-024-a — add explicit cap (`headerSize > N`) before `make([]byte, headerSize)`.
