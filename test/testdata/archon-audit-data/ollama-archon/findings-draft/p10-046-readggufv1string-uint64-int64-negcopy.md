Phase: 10
Sequence: 046
Slug: readggufv1string-uint64-int64-negcopy
Verdict: VALID
Rationale: readGGUFV1String casts a uint64 string length to int64 before passing it to io.CopyN; a value with MSB set produces a negative byte count that causes CopyN to return an error (or copy nothing), which is a distinct cast-truncation variant of AP-040 affecting GGUF v1 files.
Severity-Original: MEDIUM
PoC-Status: pending
Origin-Finding: archon/findings-draft/p8-040-gguf-string-length-panic.md
Origin-Pattern: AP-040

## Summary
`readGGUFV1String` at `fs/ggml/gguf.go:296-311` reads the string length as uint64 and casts it directly to int64 for `io.CopyN`:

```go
var length uint64
binary.Read(r, llm.ByteOrder, &length)   // attacker-controlled
io.CopyN(&b, r, int64(length))           // line 303: uint64 → int64 cast
```

`io.CopyN` with a negative `n` returns `(0, nil)` per its contract. The function then calls `b.Truncate(b.Len() - 1)` on a zero-length buffer, which panics: `runtime error: index out of range` inside `Truncate` when it tries to access `b.buf[n-1]`.

## Location
`fs/ggml/gguf.go:296-311` — `readGGUFV1String`

```go
var length uint64
if err := binary.Read(r, llm.ByteOrder, &length); err != nil { ... }
var b bytes.Buffer
if _, err := io.CopyN(&b, r, int64(length)); err != nil { ... }  // line 303
b.Truncate(b.Len() - 1)  // line 308 — panics when b.Len()==0
```

## Attacker Control
A GGUF v1 file (magic version == 1) where any string field (key or string-typed value) has its 8-byte length set to a value with MSB set (e.g. 0x8000000000000000). GGUF v1 is accepted by the parser's version switch without restriction.

## Trust Boundary Crossed
Filesystem/network → GGUF parser. Reachable via any `ggml.Decode` call site; GGUF v1 is legacy but explicitly supported.

## Impact
Panic (DoS) in the ollama server process when a v1 GGUF file is decoded. All in-flight requests are dropped. No memory corruption occurs, but service availability is lost until restart.

## Evidence
`fs/ggml/gguf.go:303,308`:
```go
if _, err := io.CopyN(&b, r, int64(length)); err != nil {
    return "", err
}
b.Truncate(b.Len() - 1)   // b.Len() == 0 → Truncate(-1) → panic
```

Per `bytes.(*Buffer).Truncate` source: panics when n < 0 or n > b.Len().

## Reproduction Steps
1. Craft a GGUF v1 file (version field = 1) with the first KV key length set to 0x8000000000000000.
2. Submit to `ollama create --from <file>` or a `pullModel` flow that calls `ggml.Decode`.
3. Observe panic: `runtime error: bytes.Buffer.Truncate: truncation out of range`.
