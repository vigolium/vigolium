# p4-f03: GGUF Parser — Unbounded String Allocation via Attacker-Controlled Length Field

**Severity**: HIGH
**CWE**: CWE-770 (Allocation of Resources Without Limits), CWE-400 (Uncontrolled Resource Consumption)
**DFD Slice**: DFD-4 (HTTP body -> blob write -> GGUF parse)
**CVE Pattern**: Matches structural recurrence pattern from CVE-2025-66960, CVE-2025-0315

## Location

- `fs/ggml/gguf.go:348-371`: `readGGUFString()`
- `fs/ggml/gguf.go:296-310`: `readGGUFV1String()`

## Description

### readGGUFString (v2/v3)

```go
// fs/ggml/gguf.go:359-364
length := int(llm.ByteOrder.Uint64(buf))  // uint64 -> int: overflow if > math.MaxInt
if length > len(llm.scratch) {            // scratch is 16KB
    buf = make([]byte, length)            // UNBOUNDED allocation
} else {
    buf = llm.scratch[:length]
}
```

A crafted GGUF with `length = 0x7FFFFFFF00000001` (on 64-bit) wraps to a negative int, causing a panic. A length of `1 << 30` (1GB) causes a 1GB heap allocation before any I/O size check. The only guard is the scratch buffer fallback path, but it does not cap the allocation.

### readGGUFV1String (v1)

```go
// fs/ggml/gguf.go:297-303
var length uint64
binary.Read(r, llm.ByteOrder, &length)
io.CopyN(&b, r, int64(length))  // int64 cast: if length > math.MaxInt64 wraps negative
```

The `bytes.Buffer` in `io.CopyN` grows without bound. A legitimate-looking length value near MaxInt64 would cause OOM before the I/O error occurs.

## Reach

Multiple callers pass `maxArraySize = -1` (uncapped):
- `server/create.go:468` — `/api/create` blob path
- `server/create.go:684` — quantize path
- `server/model.go:65` — model load
- `ml/backend/ggml/ggml.go:130` — ML backend
- `model/model.go:150` — model loading

Even callers passing `maxArraySize = 1024` only cap array entries, not individual string lengths.

## Attack

POST malicious GGUF to `/api/blobs/:digest` then POST `/api/create` → server OOM or crash.

---

## Phase 7 Enrichment Verdict

**Classification**: SECURITY — likely security (DoS against server process)

**Attacker Control**: Any client that can reach `/api/blobs/:digest` (unauthenticated by default per CVE-2025-63389 auth-bypass pattern) can upload a crafted GGUF. The string length field is a 64-bit value read directly from the attacker-supplied binary without bounds checking.

**Runtime**: The `ollama serve` HTTP server process. GGUF parsing occurs in the Go process synchronously during `/api/create` or model load. An OOM crash kills the entire server.

**Trust Boundary Crossed**: Network-to-server trust boundary. An unauthenticated remote attacker can crash the server. There is no authentication gate on blob upload in default configuration.

**Effect**: Denial of service against the server (cross-user impact on a shared/hosted Ollama instance). Not cross-privilege in isolation, but combined with the 0o777 blob directory (p4-f10), enables a two-stage attack: upload crafted GGUF -> trigger OOM on all users' model loads.

**CodeQL Reachability**: No pre-computed slice. Manual trace: `POST /api/blobs/:digest` -> `server/routes.go:BlobsHandler` -> blob written to disk -> `POST /api/create` -> `server/create.go:468` -> `llm.LoadModel(path, -1)` -> `gguf.go:readGGUFString()` -> unbounded `make([]byte, length)`. Path is direct and confirmed reachable via unauthenticated HTTP endpoints.

**KB Cross-Reference**: CVE-2025-66960 and CVE-2025-0315 describe this identical pattern. The KB notes this as a "structural recurrence" — individual CVE fixes without comprehensive input validation. The current code shows the pattern persists. Nine GGUF CVEs in the advisory inventory confirm this is an active exploitation target.

**Exploit Prerequisites**:
- Network access to `ollama serve` (localhost by default; any network if `OLLAMA_HOST=0.0.0.0`)
- No authentication required in default configuration
- Single HTTP request pair (blob upload + create)

**Verdict**: KEEP — HIGH security finding. Unauthenticated DoS reachable via standard API. Structural fix required: add an upper bound (e.g., 256MB or file-size-relative cap) to string length in `readGGUFString` before allocation.
