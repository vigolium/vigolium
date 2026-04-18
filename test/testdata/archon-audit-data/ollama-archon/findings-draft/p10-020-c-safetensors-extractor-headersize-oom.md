Phase: 10
Sequence: 020-c
Slug: safetensors-extractor-headersize-oom
Verdict: VALID
Rationale: x/safetensors/extractor.go and x/imagegen/safetensors/safetensors.go both read a uint64 header-size field from the first 8 bytes of a safetensors file and immediately pass it to make([]byte, headerSize) with no cap check, enabling an attacker-supplied safetensors file to trigger OOM via a single crafted 8-byte prefix.
Severity-Original: HIGH
PoC-Status: pending
Origin-Finding: archon/findings-draft/p8-020-gguf-shape-uint64-overflow-oob.md
Origin-Pattern: AP-020

## Summary

Two independent safetensors header parsers share the same root cause: an
unchecked `uint64 → make([]byte, N)` allocation from attacker-controlled data.

**Site A — `x/safetensors/extractor.go:194`** (package `safetensors`):

```go
var headerSize uint64
binary.Read(f, binary.LittleEndian, &headerSize)   // attacker controls first 8 bytes
headerBytes := make([]byte, headerSize)             // NO CAP CHECK
```

Called from `OpenForExtraction()` which is invoked by:
- `x/create/create.go:552` (`inspectSourceQuantization`)
- `x/create/create.go:709` (`CreateSafetensorsModel`)
- `x/create/qwen35.go:50` (Qwen3.5 safetensors create path)
- `x/create/imagegen.go:57` (image-gen model create)

All of those are reachable from `POST /api/create` with a Modelfile that
references a local safetensors directory.

**Site B — `x/imagegen/safetensors/safetensors.go:38`** (package `safetensors`):

```go
var headerSize uint64
binary.Read(f, binary.LittleEndian, &headerSize)   // attacker controls first 8 bytes
headerBytes := make([]byte, headerSize)             // NO CAP CHECK
```

Called from `parseSafetensorHeader()` → `LoadModelWeights()` /
`LoadModelWeightsFromPaths()`.  This is the image-generation weight loader.

Compare with the protected paths:
- `x/server/show.go:380` has `if headerSize > 1024*1024 { return error }`
- `x/mlxrunner/model/root.go:117` has `if headerSize > 100*1024*1024 { return error }`
- `x/imagegen/manifest/manifest.go:299` has `if headerSize > 1024*1024 { return error }`

The two vulnerable sites lack this guard entirely.

The root cause is the same class as the confirmed AP-024 finding
(`convert/reader_safetensors.go` int64 OOM), but here the field is uint64 and
there is no capacity guard at all, making the maximum allocation 2^64-1 bytes.

## Location

- `x/safetensors/extractor.go:188-194` — `OpenForExtraction` uncapped `make([]byte, headerSize)`
- `x/imagegen/safetensors/safetensors.go:33-38` — `parseSafetensorHeader` uncapped `make([]byte, headerSize)`

## Attacker Control

**Via `x/safetensors/extractor.go`**: The attacker supplies a directory
containing a file with `.safetensors` extension whose first 8 bytes encode a
large `uint64` value (e.g. `0x0000000010000000` = 256 MiB).  This directory is
specified in the `FROM <dir>` clause of a Modelfile sent to `POST /api/create`.
No authentication is required on the default loopback-only configuration.

**Via `x/imagegen/safetensors`**: The attacker supplies a directory path to the
image-generation engine (through the model manifest's layer reference for
image-gen models).

## Trust Boundary Crossed

Network API (`POST /api/create`) → Go runtime allocator; a single malformed
safetensors file causes the server process to request gigabytes of heap from
the OS, triggering OOM killer or hanging all Go GC workers.

## Impact

- **Denial of service (OOM)**: `make([]byte, 2^34)` = 16 GiB allocation on a
  typical server causes OOM kill of the Ollama process.
- **No authentication required**: `POST /api/create` is unauthenticated by
  default (loopback-only, but AP-060/AP-061 break that fence).
- Chained with AP-026 (symlink follow in safetensors enumeration): an attacker
  who controls only a symlink target (not a real directory write) can point the
  extractor at a crafted file, combining path traversal with OOM.

## Evidence

```go
// x/safetensors/extractor.go:186-197
func OpenForExtraction(path string) (*TensorExtractor, error) {
    f, err := os.Open(path)
    ...
    var headerSize uint64
    if err := binary.Read(f, binary.LittleEndian, &headerSize); err != nil {
        ...
    }
    headerBytes := make([]byte, headerSize)  // NO CAP -- attacker-controlled uint64
    if _, err := f.Read(headerBytes); err != nil {
        ...
    }
    ...
}

// x/imagegen/safetensors/safetensors.go:26-50
func parseSafetensorHeader(path string) (SafetensorHeader, error) {
    f, err := os.Open(path)
    ...
    var headerSize uint64
    if err := binary.Read(f, binary.LittleEndian, &headerSize); err != nil {
        ...
    }
    headerBytes := make([]byte, headerSize)  // NO CAP -- attacker-controlled uint64
    ...
}

// CONTRAST: protected callers elsewhere in codebase:
// x/server/show.go:379-381
if headerSize > 1024*1024 {
    return nil, fmt.Errorf("header size too large: %d", headerSize)
}
// x/mlxrunner/model/root.go:117-119
if headerSize > 100*1024*1024 {
    return nil, "", 0, fmt.Errorf("header too large: %d", headerSize)
}
```

## Reproduction Steps

1. Create a file `payload.safetensors` with 8-byte content
   `\x00\x00\x00\x00\x10\x00\x00\x00` (headerSize = 268435456 = 256 MiB).
2. Place it in a directory `/tmp/crafted/`.
3. `POST /api/create` with Modelfile `FROM /tmp/crafted/payload.safetensors`
   (triggers `inspectSourceQuantization` → `OpenForExtraction`).
4. Observe: server process RSS spikes by 256 MiB per request, leading to OOM
   under sustained load or a single 16-GiB request.

Fix: add `if headerSize > 100*1024*1024 { return error }` in both
`OpenForExtraction` and `parseSafetensorHeader`, consistent with the protected
callers already in the codebase.
