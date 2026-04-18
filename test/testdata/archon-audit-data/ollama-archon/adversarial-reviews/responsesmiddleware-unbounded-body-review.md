# Adversarial Review: p8-075 ResponsesMiddleware unbounded body

## Step 1 — Restated Claim and Sub-claims

**Restated claim**: The `ResponsesMiddleware` gin handler for `/v1/responses` performs an unbounded `io.ReadAll` on the incoming HTTP request body, providing a single-request OOM DoS primitive distinct from p8-063's `cloud_proxy.readRequestBody` sink.

**Sub-claims**:
- A: Attacker can direct arbitrary-size HTTP bodies to an endpoint served by `ResponsesMiddleware`.
- B: `ResponsesMiddleware` contains `io.ReadAll(c.Request.Body)` with no `http.MaxBytesReader`, no `Content-Length` check, no chunk bound.
- C: The unbounded read causes 2-3x memory amplification and eventual OOM — independent of p8-063.

## Step 2 — Independent Code Path Trace

**Path stated in draft**: `server/middleware/openai.go:511-523` — wrong.
**Actual path at commit 57653b8e**: `/Users/bytedance/Desktop/demo/ollama/middleware/openai.go:509-571`.

Reading the function directly:

- Line 509: `func ResponsesMiddleware() gin.HandlerFunc`
- Lines 511-520: zstd branch only — wraps the decompressed reader in `http.MaxBytesReader(c.Writer, io.NopCloser(reader), maxDecompressedBodySize)` (20 MiB cap, `middleware/openai.go:22`).
- Line 522: `var req openai.ResponsesRequest`
- Line 523: `if err := c.ShouldBindJSON(&req); err != nil { ... }`
- Lines 540-546: re-encodes `chatReq` into a `bytes.Buffer`, replaces `c.Request.Body`.

**There is no `io.ReadAll` call anywhere in `ResponsesMiddleware`.** `grep -n "io.ReadAll" middleware/openai.go` returns only line 747 (audio transcription helper, unrelated).

`ShouldBindJSON` in gin v1.10.0 (`go.mod`: `github.com/gin-gonic/gin v1.10.0`) delegates to `binding/json.go:44 decodeJSON`:

```go
decoder := json.NewDecoder(r)
...
if err := decoder.Decode(obj); err != nil {
```

`encoding/json.Decoder` is a streaming decoder — it does NOT materialize the full body into a single byte slice before decoding. Memory usage scales with the size of the largest individual string/array value in the JSON, not with a redundant intermediate buffer.

**Route registration** (`server/routes.go:1725`):

```
r.POST("/v1/responses", s.withInferenceRequestLogging("/v1/responses",
    cloudPassthroughMiddleware(cloudErrRemoteInferenceUnavailable),
    middleware.ResponsesMiddleware(),
    s.ChatHandler)...)
```

`cloudPassthroughMiddleware` runs FIRST. At `server/cloud_proxy.go:97` it calls `readRequestBody(c.Request)`, which (line 294) is `io.ReadAll(r.Body)` with no cap. It then replaces `c.Request.Body` with `io.NopCloser(bytes.NewReader(body))`. So by the time `ResponsesMiddleware` runs, the body is already fully buffered in memory — buffered by the p8-063 sink, not by `ResponsesMiddleware`.

**ResponsesMiddleware is never reached without passing through `cloudPassthroughMiddleware`**. `grep -rn "ResponsesMiddleware()"` finds exactly one production registration (`routes.go:1725`) and one test usage (`middleware/openai_test.go:1591`).

## Step 3 — Protection Surface Search

| Layer | Control | Blocks finding? |
|-------|---------|-----------------|
| Framework | gin `ShouldBindJSON` uses streaming `json.Decoder` — no intermediate `io.ReadAll` | YES (blocks the specific `io.ReadAll` sink claimed in the finding) |
| Framework | gin has no default body-size limit | (irrelevant — the claimed sink doesn't exist) |
| Middleware | zstd branch DOES have `http.MaxBytesReader(..., maxDecompressedBodySize)` at `middleware/openai.go:518` | Partial — only the zstd branch is capped |
| Upstream | `cloudPassthroughMiddleware` runs before `ResponsesMiddleware` and does its own `io.ReadAll` at `cloud_proxy.go:294` | This is NOT a protection; it is p8-063's sink. The memory pressure observed on `/v1/responses` is attributable to p8-063, not to `ResponsesMiddleware`. |

## Step 4 — Real-Environment Reproduction

Built ollama at commit `57653b8e` to `/tmp/ollama-p8-075`. Ran `OLLAMA_HOST=127.0.0.1:11464 /tmp/ollama-p8-075 serve`. Healthcheck: `curl http://127.0.0.1:11464/` returned `Ollama is running`.

**Attempt 1**: Sent a 200 MiB JSON body with a huge `instructions` field via `curl -X POST /v1/responses`.

Results (RSS samples every 0.5s, KB):
```
initial: 29,968
peak:    1,781,728   (~1.78 GiB)
steady:  1,781,728
HTTP status: 404 (model 'x' not found)
Time: 3.5s
```

Amplification: ~9x the body size. Process did not OOM (200 MiB body on a dev machine).

**Critical attribution question**: Does the observed 1.78 GiB RSS growth prove the `ResponsesMiddleware` `io.ReadAll` sink, or does it prove p8-063's `cloud_proxy.readRequestBody` sink?

Tracing the request flow for `model="x"` (not a cloud-registered model):
1. `cloudPassthroughMiddleware` fires (line 73, method==POST)
2. Content-Encoding is not zstd, so zstd branch is skipped
3. `readRequestBody(c.Request)` → `io.ReadAll(r.Body)` → **buffers 200 MB here** (p8-063 sink)
4. `extractModelField` → returns "x"
5. `parseAndValidateModelRef("x")` → Source != modelSourceCloud → `c.Next()`
6. `ResponsesMiddleware` runs → `ShouldBindJSON` streams-decodes from the already-buffered bytes → allocates ~200 MB string for `Instructions`
7. `json.NewEncoder(&b).Encode(chatReq)` → another ~200 MB buffer

Of the ~1.78 GiB peak RSS, the primary driver is (3) — the p8-063 sink — plus GC lag. The `ShouldBindJSON` call in step 6 does allocate a large string in the decoded struct, but (a) it reads from a `bytes.Reader` over already-in-memory bytes, so it is not reading from the wire, and (b) there is no `io.ReadAll` call. The re-encoding in step 7 is a legitimate amplification, but that is not what the finding claims.

**Isolation test**: If `cloud_proxy.readRequestBody` were wrapped in `MaxBytesReader` (the p8-063 fix), the body passed to `ResponsesMiddleware` would already be bounded, and `ResponsesMiddleware` would not be able to blow memory — there is no independent sink here.

Evidence saved at `/Users/bytedance/Desktop/demo/ollama/archon/real-env-evidence/p8-075-responsesmiddleware-unbounded-body/`.

## Step 5 — Prosecution and Defense Briefs

### Prosecution Brief

Real-environment reproduction shows a single 200 MiB POST to `/v1/responses` drives the ollama process RSS from 30 MiB to 1.78 GiB (9x amplification). With a 4 GiB body, linear extrapolation predicts OOM on most production machines. The `/v1/responses` endpoint is bound whenever ollama serves (loopback by default, 0.0.0.0 when `OLLAMA_HOST` is set). No authentication required. Even if the precise line cited in the draft is wrong, the `/v1/responses` endpoint is a real unbounded-memory attack surface. Remediation (`http.MaxBytesReader` at middleware entry) would be appropriate at this layer as defense-in-depth.

### Defense Brief

The finding's core factual claim is wrong: `ResponsesMiddleware` does NOT call `io.ReadAll`. It uses `c.ShouldBindJSON(&req)`, which in gin v1.10.0 (`binding/json.go:44`) uses a streaming `json.NewDecoder(r).Decode(obj)` — this is explicitly not buffering the full body. The memory amplification observed in real-env reproduction is fully attributable to `cloud_proxy.readRequestBody` at `server/cloud_proxy.go:289-301`, which runs as a predecessor middleware on every POST to `/v1/responses` and performs the actual unbounded `io.ReadAll`. That sink is already covered by the separately-filed p8-063. The finding draft's "distinct from p8-063" claim ("the on-host translation path — the bytes stay on the ollama process, get JSON-decoded, then re-encoded, further amplifying transient memory usage") is misattribution: the re-encoding step amplifies GC pressure but it does not add a new unbounded-read sink — it operates on bytes that are already bounded by whatever cap is applied at `cloud_proxy.readRequestBody`. Fixing p8-063 eliminates the observed DoS on `/v1/responses` without any change to `ResponsesMiddleware`. Therefore p8-075 as written is both factually incorrect (no such `io.ReadAll` exists) and operationally subsumed by p8-063.

## Step 6 — Severity Challenge

Starting at MEDIUM. The factual claim is wrong (no `io.ReadAll` in `ResponsesMiddleware`). The observed DoS on `/v1/responses` is entirely attributable to p8-063's sink. There is no independent primitive here. No upgrade warranted; finding must be disproved.

## Step 7 — Verdict

**DISPROVED**

- Sub-claim B fails: the code point described does not exist. `ResponsesMiddleware` uses `c.ShouldBindJSON`, a streaming decoder, not `io.ReadAll`.
- Sub-claim C fails on attribution: the DoS observed is produced by `cloud_proxy.readRequestBody` (p8-063), not by `ResponsesMiddleware`.

**Severity-Final**: N/A (DISPROVED — subsumed by p8-063)
**PoC-Status**: executed (reproduction ran successfully; memory growth observed but attributable to p8-063, not to the claimed sink)
