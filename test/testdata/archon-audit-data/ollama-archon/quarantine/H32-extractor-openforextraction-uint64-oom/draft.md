Phase: 10
Sequence: 000
Slug: extractor-openforextraction-uint64-oom
Verdict: VALID
Rationale: x/safetensors/extractor.go OpenForExtraction reads a uint64 headerSize from attacker-controlled safetensors file and calls make([]byte, headerSize) with no cap, enabling instant OOM identical in mechanism to p8-024.
Severity-Original: HIGH
Severity-Final: HIGH
PoC-Status: pending
Origin-Finding: archon/findings-draft/p8-024-safetensors-header-int64-oom.md
Origin-Pattern: AP-024

## Summary

`x/safetensors/extractor.go:188-197` (`OpenForExtraction`) reads an 8-byte little-endian `uint64` headerSize from the file and immediately allocates `make([]byte, headerSize)` with no cap against file size or a hard ceiling. A crafted safetensors blob with headerSize = 0xFFFFFFFFFFFFFFFF causes `runtime.mallocgc` to panic with an unrecoverable "makeslice: cap out of range" or trigger a kernel OOM-kill before the subsequent `f.Read(headerBytes)` can return an error.

Unlike the original finding (AP-024 in `convert/reader_safetensors.go`) where the field was mistyped as `int64`, this parser correctly declares `uint64` per the safetensors spec but still omits any cap check, so the unsigned value ranges from 0 to 2^64-1 — all of which are passed directly to `make`.

## Location

`x/safetensors/extractor.go:188-197` function `OpenForExtraction`

```go
var headerSize uint64
if err := binary.Read(f, binary.LittleEndian, &headerSize); err != nil {
    f.Close()
    return nil, fmt.Errorf("failed to read header size: %w", err)
}

headerBytes := make([]byte, headerSize)   // <-- uncapped allocation
if _, err := f.Read(headerBytes); err != nil {
    f.Close()
    return nil, fmt.Errorf("failed to read header: %w", err)
}
```

## Attacker Control

`OpenForExtraction` is called from:
- `x/create/create.go:552` and `x/create/create.go:709` — `CreateSafetensorsModel` iterates a user-supplied model directory and passes each `.safetensors` file directly to `OpenForExtraction`.
- `x/create/qwen35.go:50` — same path for Qwen3.5 models.
- `x/create/imagegen.go:57` — image-generation model creation path.

All callers originate from `POST /api/create` (non-experimental) accepting a Modelfile whose FROM clause points to a directory. No trust boundary separates the file bytes from the allocation size.

## Trust Boundary Crossed

HTTP API (unauthenticated by default) / local filesystem -> process heap -> kernel OOM-killer.

## Impact

Same as p8-024: instant unrecoverable OOM or runtime panic when gin.Recovery cannot catch `runtime: out of memory`. Crashes the entire `ollama serve` process. Requires local filesystem write access to place a crafted `.safetensors` file, or control of a directory path referenced in a Modelfile sent via `POST /api/create`.

## Evidence

```
// x/safetensors/extractor.go:186-197
func OpenForExtraction(path string) (*TensorExtractor, error) {
    f, err := os.Open(path)
    ...
    var headerSize uint64
    if err := binary.Read(f, binary.LittleEndian, &headerSize); err != nil {
        f.Close()
        return nil, fmt.Errorf("failed to read header size: %w", err)
    }

    headerBytes := make([]byte, headerSize)  // NO CAP - headerSize up to 2^64-1
    if _, err := f.Read(headerBytes); err != nil {
```

Contrast with the safe sibling `x/mlxrunner/model/root.go:117-119`:
```go
if headerSize > 100*1024*1024 {
    return nil, "", 0, fmt.Errorf("header too large: %d", headerSize)
}
```
and `x/server/show.go:380-382`:
```go
if headerSize > 1024*1024 {
    return nil, fmt.Errorf("header size too large: %d", headerSize)
}
```
Those functions applied the fix; `OpenForExtraction` did not.

## Reproduction Steps

1. Create a file `evil.safetensors` whose first 8 bytes are `\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF` (uint64 max).
2. Place it in a directory alongside a minimal `config.json`.
3. `POST /api/create` with a Modelfile `FROM /path/to/evil-dir`.
4. Observe process crash / OOM-kill — identical to the p8-024 primitive.

Fix direction: add `if headerSize > maxSafetensorsHeaderSize { return nil, fmt.Errorf(...) }` before `make([]byte, headerSize)`, matching the guard already present in `x/mlxrunner/model/root.go`.
