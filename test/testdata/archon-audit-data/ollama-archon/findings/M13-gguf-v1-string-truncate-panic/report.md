## Summary

`fs/ggml/gguf.go:296-311 readGGUFV1String` reads a uint64 length, then copies exactly `int64(length)` bytes via `io.CopyN`, then truncates the trailing null terminator with `b.Truncate(b.Len() - 1)`. For `length >= 2^63`, `int64(length)` wraps to a negative value. `io.CopyN` with negative n returns `(0, nil)` (per stdlib behavior). The buffer is then empty (`b.Len() == 0`), and `Truncate(-1)` panics with "bytes.Buffer: truncation out of range".

## Details

`fs/ggml/gguf.go:296-311 readGGUFV1String` reads a uint64 length, then copies exactly `int64(length)` bytes via `io.CopyN`, then truncates the trailing null terminator with `b.Truncate(b.Len() - 1)`. For `length >= 2^63`, `int64(length)` wraps to a negative value. `io.CopyN` with negative n returns `(0, nil)` (per stdlib behavior). The buffer is then empty (`b.Len() == 0`), and `Truncate(-1)` panics with "bytes.Buffer: truncation out of range".

### Location

`fs/ggml/gguf.go:296-311`

### Attacker Control

Any GGUF V1 blob. V1 is legacy but still accepted by the parser; attacker simply chooses V1 format.

### Trust Boundary Crossed

Network API -> process panic.

### Evidence

```
// fs/ggml/gguf.go:296-311
func readGGUFV1String(llm *gguf, r io.Reader) (string, error) {
    var length uint64
    if err := binary.Read(r, llm.ByteOrder, &length); err != nil {
        return "", err
    }

    var b bytes.Buffer
    if _, err := io.CopyN(&b, r, int64(length)); err != nil {
        return "", err
    }

    // gguf v1 strings are null-terminated
    b.Truncate(b.Len() - 1)     // panics if Len() == 0

    return b.String(), nil
}
```

## Root Cause

Validated rationale: readGGUFV1String reads a uint64 length, casts to int64 for io.CopyN (which treats negative as zero-read), then unconditionally calls b.Truncate(b.Len()-1); for a zero-read buffer this is Truncate(-1) which panics. Affects V1 legacy GGUFs.

Primary cited code reference: `fs/ggml/gguf.go:296`.

Merge extraction sink line: `fs/ggml/gguf.go:296-311`

## Proof of Concept

Merge-normalized status: `pending`.

No concrete evidence artifacts were preserved under `evidence/` during the merge.

1. Craft a GGUF with version=1, any KV string whose length field = 0x8000000000000000.
2. `POST /api/create` referencing the blob.
3. Observe 500; process survives via gin.Recovery.

Fix direction: `if length > math.MaxInt64 { return "", errors.New("length too large") }`; also `if b.Len() == 0 { return "", errors.New("empty V1 string") }` before Truncate.

## Impact

Recoverable panic -> per-request 500 when reached from HTTP handler. V1 rarity narrows blast radius but does not prevent the attack since the attacker chooses the format.

_Synthesized during merge normalization from `archon/findings/M13-gguf-v1-string-truncate-panic/draft.md`._
