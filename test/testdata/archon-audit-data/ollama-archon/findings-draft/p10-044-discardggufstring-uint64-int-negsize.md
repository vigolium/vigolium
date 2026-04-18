Phase: 10
Sequence: 044
Slug: discardggufstring-uint64-int-negsize
Verdict: VALID
Rationale: discardGGUFString performs the identical uint64→int cast as p8-040/readGGUFString, allowing an attacker-controlled length value > MaxInt64 to produce a negative size, causing the drain loop to be silently skipped and the parser to continue reading from the wrong file offset.
Severity-Original: HIGH
PoC-Status: pending
Origin-Finding: archon/findings-draft/p8-040-gguf-string-length-panic.md
Origin-Pattern: AP-040

## Summary
`discardGGUFString` at `fs/ggml/gguf.go:337` reads an 8-byte length from the binary stream and casts it to `int` with no bounds check: `size := int(llm.ByteOrder.Uint64(buf))`. On a 64-bit system where `int` is 64 bits, a uint64 value with the MSB set (e.g. 0x8000_0000_0000_0001) produces a negative `size`. The drain loop `for size > 0` is never entered, so the function returns `nil` without consuming any bytes. The parser then continues reading subsequent keys from the wrong offset, producing corrupt KV data or a panic when later type assertions fail.

## Location
`fs/ggml/gguf.go:330-346` — `discardGGUFString`

```go
size := int(llm.ByteOrder.Uint64(buf))   // line 337 — unchecked cast
for size > 0 {                            // line 338 — skipped when size < 0
    n, err := r.Read(llm.scratch[:min(size, cap(llm.scratch))])
    ...
    size -= n
}
```

Called from:
- `readGGUFV1StringsData` (line 323) for oversized string arrays in v1 files
- `readGGUFStringsData` (line 397, indirect via `readGGUFStringsData` fallthrough) — only when `a.values == nil`

## Attacker Control
A GGUF v1 binary file with a string-typed array KV entry where one element's length field has MSB set. The file need only be parseable up to that point; no authentication is required when the file is supplied via the `/api/create` endpoint (FROM or model path) or via `ollama pull` from an attacker-controlled registry.

## Trust Boundary Crossed
Filesystem/network → GGUF parser. Same boundary as p8-040.

## Impact
Silent offset desynchronisation: the parser reads subsequent key names and type tags from data inside the supposed string body, leading to:
1. Corrupt KV map populated with attacker-controlled garbage.
2. Downstream type assertions on KV values panic (nil-dereference or type mismatch).
3. Potential read of arbitrary bytes into KV keys/values, enabling further exploitation via corrupt metadata.

## Evidence
`fs/ggml/gguf.go:337`:
```go
size := int(llm.ByteOrder.Uint64(buf))
```
No guard of the form `if size < 0 { return fmt.Errorf(...) }` exists.

## Reproduction Steps
1. Craft a GGUF v1 file containing a KV entry of type `ggufTypeArray` / element type `ggufTypeString`.
2. Set the array element count to 1.
3. Set the element's 8-byte length field to `0x8000000000000001`.
4. Because `maxArraySize` check applies only after the array is allocated with `size` elements and `discardGGUFString` is called when `a.values == nil` (oversized), the drain loop is skipped.
5. Feed the file to `ollama create --from <file>` and observe subsequent panic or corrupt KV.
