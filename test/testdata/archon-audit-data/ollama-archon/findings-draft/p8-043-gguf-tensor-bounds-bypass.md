Phase: 8
Sequence: 043
Slug: gguf-tensor-bounds-bypass
Verdict: VALID
Rationale: CVE-fix tensor bounds check at gguf.go:258-262 is bypassed via uint64 shape product overflow (wraps to 0) or unknown tensor Kind (typeSize=0); accepts tensors with fraudulent metadata that may cause OOB access in downstream llama.cpp backend. Advocate confirmed no alternate validation exists.
Severity-Original: HIGH
PoC-Status: pending
Pre-FP-Flag: none
Debate: archon/chamber-workspace/chamber-C/debate.md

## Summary

The GGUF parser validates tensor data bounds by computing `tensorEnd = tensorOffset + tensor.Offset + tensor.Size()` and checking against file size. However, `Tensor.Size()` can return 0 through two attack vectors: (A) Shape product overflow where uint64 multiplication wraps (e.g., shape=[0x8000000000000000, 2] -> Elements()=0), and (B) unknown tensor Kind where `TypeSize()` returns 0 from the default switch case. When Size()=0, the bounds check passes trivially regardless of actual tensor data requirements. The tensor with fraudulent metadata is accepted and stored in `llm.tensors`, potentially reaching the llama.cpp backend which may use the shapes for memory addressing.

## Location

- **Elements overflow**: `fs/ggml/ggml.go:505-511` -- `count *= n` wraps uint64
- **TypeSize zero**: `fs/ggml/ggml.go:500-502` -- `default: return 0`
- **Size computation**: `fs/ggml/ggml.go:513-514` -- `Elements() * typeSize() / blockSize()`
- **Bounds check bypass**: `fs/ggml/gguf.go:258-262` -- `tensorEnd > uint64(fileSize)`
- **Entry point**: `POST /api/create` -> `ggml.Decode`

## Attacker Control

The attacker controls tensor Shape ([]uint64) and Kind (uint32) fields in the GGUF binary. These are read directly from the file without validation beyond the bypassed bounds check.

**Attack vector A**: Set shape dimensions such that their product overflows uint64 to 0 (e.g., [0x8000000000000000, 2]).
**Attack vector B**: Set Kind to an undefined value (e.g., 0xFFFFFFFF) so typeSize()=0.

## Trust Boundary Crossed

Network (unauthenticated HTTP) -> GGUF parser -> tensor metadata storage -> potential downstream C++ backend (llama.cpp). The Go parser's acceptance of fraudulent tensor metadata may be trusted by the inference runtime.

## Impact

- **Immediate**: Bounds check bypass allows malformed tensors to be accepted. This defeats a security control added specifically to prevent GGUF-based attacks.
- **Downstream**: If llama.cpp trusts Go-parsed tensor shapes for memory allocation/addressing, this enables out-of-bounds memory access in the C++ runtime (potential code execution). This downstream path needs deeper investigation (PH-R3-06).
- **Authentication**: None required.

## Evidence

1. `fs/ggml/ggml.go:505-511` -- `Elements()`: `count *= n` for each shape dimension (uint64 overflow possible)
2. `fs/ggml/ggml.go:500-502` -- `TypeSize()` default case returns 0 for unknown Kind values
3. `fs/ggml/ggml.go:513-514` -- `Size()`: `Elements() * typeSize() / blockSize()` = 0 when either factor is 0
4. `fs/ggml/gguf.go:258-262` -- bounds check: `tensorEnd > uint64(fileSize)` passes when Size()=0
5. `fs/ggml/ggml.go:428-429` -- `blockSize()` default case returns 256 for unknown Kind
6. Deep probe PH-09/PH-16/PH-R3-03 validated both overflow and unknown-Kind vectors

## Reproduction Steps

1. Create a GGUF file with one tensor: shape=[0x8000000000000000, 2], Kind=TensorTypeF32, Offset=0
2. File can be minimal (just headers + KV + tensor metadata, no actual tensor data needed since Size()=0 passes bounds check)
3. Upload via `POST /api/blobs/sha256:<hash>`
4. Send `POST /api/create` referencing the digest
5. Verify tensor is accepted without error (check server logs or successful model creation)
6. For downstream impact: monitor llama.cpp memory access patterns when loading the model
