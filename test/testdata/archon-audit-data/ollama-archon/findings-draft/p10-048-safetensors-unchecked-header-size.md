Phase: 10
Sequence: 048
Slug: safetensors-unchecked-header-size
Verdict: VALID
Rationale: parseSafetensors reads an 8-byte header length as int64 from the file without any bounds check and passes it directly to make([]byte, 0, n) and io.CopyN; a negative value causes a panic due to negative capacity, and a large positive value causes OOM — mirroring the AP-041 unbounded allocation pattern in a separate binary parser.
Severity-Original: HIGH
PoC-Status: pending
Origin-Finding: archon/findings-draft/p8-041-gguf-oom-unbounded-array.md
Origin-Pattern: AP-041

## Summary
`parseSafetensors` in `convert/reader_safetensors.go:25-81` reads the safetensors header length as a raw int64 from the first 8 bytes of each file without any size validation:

```go
var n int64
if err := binary.Read(f, binary.LittleEndian, &n); err != nil { ... }  // line 35

b := bytes.NewBuffer(make([]byte, 0, n))   // line 39 — no bounds check on n
if _, err = io.CopyN(b, f, n); err != nil { ... }  // line 40
```

**When n is negative** (MSB set in the 8-byte header field): `make([]byte, 0, n)` panics immediately with `runtime: makeslice: cap out of range` — a process-killing panic.

**When n is a large positive value** (e.g. 0x0fff_ffff_ffff_ffff): the `make` succeeds and `io.CopyN` attempts to read ~1 exabyte from the file, exhausting all available memory and causing an OOM kill.

Note: The `x/server/show.go:parseSafetensorsHeader` function (a separate implementation) does have a 1 MB sanity check. The `convert/reader_safetensors.go` implementation used by the model conversion pipeline has no such guard.

## Location
`convert/reader_safetensors.go:34-41` — `parseSafetensors`

```go
var n int64
if err := binary.Read(f, binary.LittleEndian, &n); err != nil {
    return nil, err
}

b := bytes.NewBuffer(make([]byte, 0, n))   // panics if n < 0
if _, err = io.CopyN(b, f, n); err != nil { // OOM if n >> file size
    return nil, err
}
```

## Attacker Control
The header length field is the first 8 bytes of a safetensors file. An attacker supplies a crafted `.safetensors` file via:
- `POST /api/create` with a Modelfile pointing to a local directory or URL containing the malicious file
- Any path that calls `convert.ConvertModel` (server/create.go:438)

No authentication is required by default when ollama is bound to localhost and accessed from a browser (see AP-001 for CORS bypass). When bound to 0.0.0.0, it is directly internet-accessible.

## Trust Boundary Crossed
Uploaded model file / FROM directory → `convert.ConvertModel` → `parseSafetensors`. Network/filesystem boundary crossed with no intermediate validation.

## Impact
- **Negative n**: immediate panic kills the server process (DoS, all in-flight requests dropped).
- **Large positive n**: OOM causes process or host-level kill depending on kernel OOM configuration.
- No memory-safety exploit beyond DoS on this Go path, but availability is fully lost.

## Evidence
Contrast with the bounded implementation in `x/server/show.go:375-381`:
```go
var headerSize uint64
...
if headerSize > 1024*1024 {
    return nil, fmt.Errorf("header size too large: %d", headerSize)
}
```

`convert/reader_safetensors.go` has no equivalent guard.

## Reproduction Steps
1. Create a file named `model.safetensors` with the first 8 bytes set to `\xff\xff\xff\xff\xff\xff\xff\xff` (n = -1 as int64).
2. Place it in a directory and POST to `/api/create`:
   ```
   FROM /path/to/dir
   ```
3. Server panics: `runtime: makeslice: cap out of range` or equivalent.
4. Alternatively set bytes to `\xff\xff\xff\xff\xff\xff\xff\x0f` for a large positive value to trigger OOM.
