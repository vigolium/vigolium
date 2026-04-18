Phase: 10
Sequence: 051
Slug: safetensors-unbounded-oom
Verdict: VALID
Rationale: x/imagegen safetensors parser allocates make([]byte, headerSize) from a raw attacker-controlled uint64 with no size cap, enabling remote OOM crash via crafted model blob.
Severity-Original: HIGH
PoC-Status: pending
Origin-Finding: archon/findings-draft/p8-041-gguf-oom-unbounded-array.md
Origin-Pattern: AP-041

## Summary

Both `x/imagegen/safetensors/safetensors.go` (parseSafetensorHeader) and `x/imagegen/safetensors/extractor.go` (NewTensorExtractor) read a `uint64` header size from the first 8 bytes of a safetensors file and immediately allocate `make([]byte, headerSize)` with no upper bound check. An attacker-controlled model blob with `headerSize = 0xFFFFFFFFFFFFFFFF` will cause the runtime to attempt a 16 EiB allocation, triggering OOM/panic and crashing the imagegen process. This is structurally identical to AP-041 (GGUF unbounded array via -1 sentinel), but applies to the imagegen subsystem's safetensors format parser.

By contrast, `x/imagegen/manifest/manifest.go:readBlobHeader` has a proper guard (`if headerSize > 1024*1024 { return nil, fmt.Errorf("header too large") }`). The safetensors parsers lack this protection entirely.

## Location

- `x/imagegen/safetensors/safetensors.go:33-38` -- `parseSafetensorHeader`: `var headerSize uint64; binary.Read(..., &headerSize); make([]byte, headerSize)` -- no bounds check
- `x/imagegen/safetensors/extractor.go:189-195` -- `NewTensorExtractor`: same pattern, same omission

## Attacker Control

An attacker who can place a crafted `.safetensors` file in the blob directory (via supply-chain model push, MITM blob substitution, or local blob cache poisoning as in p8-044) controls the `headerSize` field. Setting the first 8 bytes to `\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF` causes an unbounded allocation.

## Trust Boundary Crossed

Remote model registry (attacker-controlled blob) -> local imagegen process memory. The blob is loaded via `manifest.LoadManifest` -> `BlobPath` -> `parseSafetensorHeader` without integrity re-verification.

## Impact

- OOM crash / SIGKILL of the imagegen process or full host OOM
- Denial of service for all image generation functionality
- Can be chained with p8-044 (blob cache poisoning) for remote delivery

## Evidence

1. `x/imagegen/safetensors/safetensors.go:38`: `headerBytes := make([]byte, headerSize)` -- headerSize is raw uint64 from file
2. `x/imagegen/safetensors/extractor.go:195`: same pattern
3. Contrast: `x/imagegen/manifest/manifest.go:299`: `if headerSize > 1024*1024 { return nil, fmt.Errorf("header too large: %d", headerSize) }` -- the manifest reader has the guard; the safetensors reader does not
4. `x/imagegen/safetensors/safetensors.go:83-116`: `LoadModelWeights` calls `parseSafetensorHeader` for every `.safetensors` file in the model directory

## Reproduction Steps

1. Create a malicious safetensors blob: 8-byte little-endian value `0xFFFFFFFFFFFFFFFF` followed by any content
2. Push a model with this blob to a registry, or substitute a cached blob (see p8-044)
3. Call the imagegen server's generate endpoint referencing the model
4. Observe OOM/process crash when `parseSafetensorHeader` allocates `make([]byte, 0xFFFFFFFFFFFFFFFF)`
