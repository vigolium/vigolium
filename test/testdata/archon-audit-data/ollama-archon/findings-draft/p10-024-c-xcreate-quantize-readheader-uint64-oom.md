Phase: 10
Sequence: p10-024-c
Slug: xcreate-quantize-readheader-uint64-oom
Verdict: VALID
Rationale: x/create/client/quantize.go readSafetensorsHeader reads uint64 headerSize and calls make([]byte, headerSize) with no cap, triggering OOM during the MLX quantization pipeline reachable from POST /api/create.
Severity-Original: HIGH
PoC-Status: pending
Origin-Finding: archon/findings-draft/p8-024-safetensors-header-int64-oom.md
Origin-Pattern: AP-024

## Summary

`x/create/client/quantize.go:518-538` (`readSafetensorsHeader`) reads an 8-byte little-endian `uint64` headerSize from a safetensors blob and immediately calls `make([]byte, headerSize)` with no bounds check. This function is part of the MLX quantization client pipeline and is reached when a safetensors model undergoes client-side quantization during the model-creation flow.

This is the third independent copy of the same vulnerable parser pattern. The other two copies (p10-024-a in `x/safetensors/extractor.go` and p10-024-b in `x/imagegen/safetensors/safetensors.go`) share the root cause with this instance and the original finding.

## Location

`x/create/client/quantize.go:518-538` function `readSafetensorsHeader`

```go
func readSafetensorsHeader(path string) (map[string]safetensorsHeaderEntry, error) {
    f, err := os.Open(path)
    ...
    var headerSize uint64
    if err := binary.Read(f, binary.LittleEndian, &headerSize); err != nil {
        return nil, err
    }
    headerBytes := make([]byte, headerSize)   // <-- uncapped allocation
    if _, err := io.ReadFull(f, headerBytes); err != nil {
        return nil, err
    }
    ...
}
```

## Attacker Control

`readSafetensorsHeader` is called at `x/create/client/quantize.go:51` inside `loadAndQuantizeArray`. The call chain is:

1. `POST /api/create` with a Modelfile pointing to a model directory containing `.safetensors` files.
2. `x/create/create.go` -> `CreateSafetensorsModel` -> `loadAndQuantizeArray` (for each tensor).
3. Each tensor is written to a temp file and then `readSafetensorsHeader(tmpPath)` is called to re-read it.

Because the temp file is written from attacker-supplied data before `readSafetensorsHeader` is called, the 8 header-size bytes are entirely attacker-controlled.

## Trust Boundary Crossed

HTTP API (POST /api/create, unauthenticated by default) -> local temp filesystem -> process heap -> kernel OOM-killer.

## Impact

Instant unrecoverable OOM or runtime panic during quantization. The panic propagates upward from `loadAndQuantizeArray` into the goroutine spawned by `server/create.go`; gin.Recovery cannot prevent kernel OOM-kill when the process heap is exhausted.

## Evidence

```
// x/create/client/quantize.go:24-55 (loadAndQuantizeArray excerpt)
func loadAndQuantizeArray(r io.Reader, name, quantize string, ...) (...) {
    ...
    tmpFile.Close()
    st, err := mlx.LoadSafetensorsNative(tmpPath)
    ...
    // Find the tensor key (may differ from name for single-tensor blobs)
    header, err := readSafetensorsHeader(tmpPath)   // <-- vulnerable call
    ...
}

// x/create/client/quantize.go:518-538 (readSafetensorsHeader)
func readSafetensorsHeader(path string) (map[string]safetensorsHeaderEntry, error) {
    f, err := os.Open(path)
    ...
    var headerSize uint64
    if err := binary.Read(f, binary.LittleEndian, &headerSize); err != nil {
        return nil, err
    }
    headerBytes := make([]byte, headerSize)  // NO CAP: 0..2^64-1 bytes requested
    if _, err := io.ReadFull(f, headerBytes); err != nil {
        return nil, err
    }
    ...
}
```

## Reproduction Steps

1. Craft a safetensors tensor blob where the first 8 bytes are `\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF` (uint64 max).
2. Include it in a model directory or send it as the tensor payload in a Modelfile-based create request.
3. `POST /api/create` with the Modelfile referencing this model.
4. `loadAndQuantizeArray` writes the blob to a temp file, then `readSafetensorsHeader` tries `make([]byte, 0xFFFFFFFFFFFFFFFF)`.
5. Process OOM-kills.

Fix direction: add `if headerSize > maxSafetensorsHeaderSize { return nil, fmt.Errorf("header too large: %d", headerSize) }` immediately after reading headerSize, matching the guard in `x/mlxrunner/model/root.go:117-119`.
