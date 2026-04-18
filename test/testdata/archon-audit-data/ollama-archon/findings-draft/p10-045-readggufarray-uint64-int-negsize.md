Phase: 10
Sequence: 045
Slug: readggufarray-uint64-int-negsize
Verdict: VALID
Rationale: readGGUFArray casts the array element count n (uint64 from binary stream) to int without bounds checking before passing it to newArray; a value > MaxInt64 produces a negative size argument, which newArray stores as array.size and then iterates via `for i := range a.size` — in Go, ranging over a negative integer yields zero iterations, so the array is silently created empty regardless of the actual element count, while the stream position is not advanced.
Severity-Original: HIGH
PoC-Status: pending
Origin-Finding: archon/findings-draft/p8-040-gguf-string-length-panic.md
Origin-Pattern: AP-040

## Summary
`readGGUFArray` at `fs/ggml/gguf.go:430-437` reads the array element count as uint64 then immediately casts to int:

```go
n, err := readGGUF[uint64](llm, r)    // attacker-controlled
...
a := newArray[uint8](int(n), llm.maxArraySize)
```

When n > math.MaxInt64 (MSB set), `int(n)` is negative. `newArray` stores this as `a.size`. `readGGUFArrayData` iterates `for i := range a.size` — Go's range over a negative integer is zero iterations — so no bytes are consumed from the stream. The parser then reads the next KV pair from bytes that were supposed to be array data.

This is a structural sibling of p8-040 (`readGGUFString`) appearing in a different parser function.

## Location
`fs/ggml/gguf.go:424-479` — `readGGUFArray`

Affected lines:
- 430: `n, err := readGGUF[uint64](llm, r)` — attacker-controlled element count
- 437–470: `newArray[T](int(n), llm.maxArraySize)` — unchecked cast for all 11 element types

## Attacker Control
Any GGUF KV entry with type `ggufTypeArray`. Element count is 8 bytes at a fixed offset within the array header. The value is fully attacker-controlled with no preceding validation.

## Trust Boundary Crossed
Filesystem/network → GGUF parser. Reachable via `ollama create`, `ollama pull`, or any `ggml.Decode` call site (see AP-041 for all callers).

## Impact
1. Zero array elements consumed from stream; subsequent KV reads parse array payload bytes as KV keys/type-tags, causing type confusion.
2. If the array element type is `ggufTypeString`, readGGUFStringsData iterates zero times, advancing no bytes, so the next KV decode reads stale stream position — leading to panic or arbitrary KV injection.
3. Combined with AP-041 (maxArraySize=-1): when maxArraySize is -1 AND n is a large positive uint64 that fits in int (e.g. 0x7fff_ffff_ffff_ffff), `make([]T, size)` with size ~9×10^18 causes OOM/panic.

## Evidence
`fs/ggml/gguf.go:430,437`:
```go
n, err := readGGUF[uint64](llm, r)
...
a := newArray[uint8](int(n), llm.maxArraySize)
```
No guard such as `if n > math.MaxInt { return nil, fmt.Errorf("array too large") }`.

## Reproduction Steps
1. Craft a GGUF file with a KV entry: key="test", type=ggufTypeArray.
2. Set array element type to ggufTypeUint8, element count to 0x8000000000000001.
3. Follow with arbitrary bytes (they will be mis-parsed as the next KV).
4. Submit via `ollama create --from <file>` (uses `ggml.Decode(..., -1)`).
5. Observe parser mis-reading subsequent KV entries, resulting in panic or corrupt model metadata.
