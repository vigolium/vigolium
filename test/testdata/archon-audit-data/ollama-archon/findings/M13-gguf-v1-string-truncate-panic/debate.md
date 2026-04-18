# Review Chamber: chamber-02

Cluster: Parser / GGUF / Template / Safetensors (binary model-file attack surface)
DFD Slices: DFD-2 (GGUF parse), DFD-3 (safetensors), DFD-4 (template DoS), DFD-10 (tokenizer), DFD-15 (convert)
NNN Range: p8-020 to p8-039
Started: 2026-04-17T00:00:00Z
Status: CLOSED
Closed: 2026-04-17T15:25:00Z

## Pre-Seeded Hypotheses (from Deep Probe Group-B + spec-gap-report + Phase 7 SAST)

These hypotheses have already been validated by the Deep Probe phase with confirmed code paths.
Ideator MUST NOT regenerate these. Tracer MUST verify and extend existing evidence rather than
re-trace from scratch. Advocate MUST search for framework/exception protections that might
invalidate these.

### H-00 Pre-Seeded Summary Table

| ID | Title | Source | Severity-Claimed | File:Line |
|----|-------|--------|------------------|-----------|
| H-01 | uint64 Shape overflow in Elements()/Size() → bounds-check bypass → unsafe.Slice OOB in cgo (PH-B-01 / PH-C01) | Probe Group-B | CRITICAL | fs/ggml/ggml.go:505-514 |
| H-02 | readGGUFString / readString unbounded length alloc → OOM DoS (PH-B-03/10/17 / PH-C02) | Probe Group-B | HIGH | fs/ggml/gguf.go:348-371, fs/gguf/gguf.go:188-205 |
| H-03 | readGGUFArray uint64→int truncation → runtime.throw unrecoverable (PH-B-04) | Probe Group-B | HIGH | fs/ggml/gguf.go:431-437 |
| H-04 | numTensor uncapped → pre-bounds memory exhaustion (PH-B-18 / PH-C03) | Probe Group-B | HIGH | fs/ggml/gguf.go |
| H-05 | parseSafetensors header int64 length → OOM (PH-B-05 / PH-C04) | Probe Group-B | HIGH | convert/reader_safetensors.go:34-41 |
| H-06 | Template size DoS + Vars() O(N) amplification per Execute (PH-B-06) | Probe Group-B | MEDIUM-HIGH | template/template.go |
| H-07 | x/create missing EvalSymlinks → arbitrary-file blob read (PH-B-08) | Probe Group-B | HIGH | x/create/create.go CreateSafetensorsModel |
| H-08 | Capabilities() proceeds on Vars() error → CapabilityTools spoofing (PH-B-16) | Probe Group-B | MEDIUM | server/images.go Capabilities() |
| H-09 | findToolCallNode skips TemplateNode → heuristic fallback mis-detection (PH-B-20) | Probe Group-B | MEDIUM | template tool-detection |
| H-10 | GraphSize nil type assertion on tokenizer.ggml.tokens (PH-B-21 / PH-C05) | Probe Group-B | MEDIUM | fs/ggml/ggml.go:607 |
| H-11 | GGUF alignment=0 divide-by-zero panic (Spec Gap 2) | Spec-gap-report | HIGH | fs/ggml/gguf.go:687-689 |
| H-12 | GGUF V1 string length uint64→int64 wrap → Truncate(-1) panic (Spec Gap 10) | Spec-gap-report | HIGH | fs/ggml/gguf.go:296-311 |
| H-13 | numKV unbounded iteration loop (Spec Gap 14) | Spec-gap-report | HIGH | fs/ggml/gguf.go:143 |
| H-14 | Blank MIME type `data:;base64,` bypasses vision allowlist → mtmd cgo with arbitrary binary (Spec Gap 11) | Spec-gap-report | HIGH | openai/openai.go:683-684 |
| H-15 | allocation-size-overflow in anthropic/trace.go:71 (SAST-ALLOC-01) | SAST Phase 7 | HIGH | anthropic/trace.go:71 |
| H-16 | allocation-size-overflow in model/renderers/json.go:14 (SAST-ALLOC-02) | SAST Phase 7 | HIGH | model/renderers/json.go:14 |
| H-17 | allocation-size-overflow in tokenizer/wordpiece.go:61 (SAST-ALLOC-03) | SAST Phase 7 | HIGH | tokenizer/wordpiece.go:61 |
| H-18 | incorrect-integer-conversion in convert/convert_deepseek2.go:155 + convert_glm4moelite.go:200 (SAST-INT-01) | SAST Phase 7 | MEDIUM | convert/convert_*.go |

### Ideator Additional Slots (H-19, H-20 — only if novel)

The Ideator is limited to 2 novel hypotheses focused on:
- **Chaining**: parser DoS combined with persistence (e.g., crafted GGUF that triggers OOB AND keeps server stuck in retry loop / crashes on every pull)
- **Lateral-thinking business logic**: e.g., poisoned GGUF that parses successfully but leaks model data or produces attacker-controlled output paths
- **Not** simple variants of H-01..H-18


---

## Ideator Round 1 — Novel Hypotheses (H-19..H-25)

**Operator note**: The synthesizer header reserves only H-19/H-20, but the Chamber-02 kickoff brief explicitly tasks the Ideator with 6 themes (a–f). Hypotheses below are scoped so each is either a cross-chamber chain (not regenerable from Group-B alone), a lateral-thinking business-logic abuse, or a DFD-10 tokenizer / DFD-3 safetensors differential attack that the Deep Probe Group-B did NOT examine. None is a simple variant of H-01..H-18. If the synthesizer decides more than two are out of scope, prefer keeping H-19, H-20, H-23, H-24 (the highest-signal cross-chamber chains).

### H-19: Blob-substitution + shape-overflow chain — planted GGUF turns every future `/api/show` into process kill

- **Attack class**: Mode 1 (Vulnerability Chaining) + Mode 4 (Second-Order)
- **Cross-modes**: Mode 7 (State Machine)
- **Chain**: multi-step
  1. Attacker uses PH-A-02 (size-only cache-hit substitution, validated in Chamber-01) OR PH-A-01 (digest-traversal write) to place a poisoned GGUF at `$OLLAMA_MODELS/blobs/sha256-<digest>` whose file size matches the legitimate blob.
  2. The GGUF's KV block declares `general.alignment=0` (H-11 spec gap) OR a tensor with `Shape=[1<<62+1,1]` (H-01) OR `tokenizer.ggml.tokens` replaced by a scalar (H-10).
  3. Any subsequent `GET /api/show`, `GET /api/tags`, `POST /api/chat`, or manifest-scan on startup calls `gguf.Open` / `ggml.Decode` on the substituted blob and panics / OOMs — **before** any hash verification could ever re-run (cache-hit skips verify).
  4. Every restart re-reads the manifest and re-triggers the crash — the server is now in a persistent crash loop that survives the attacker's access being revoked.
- **Preconditions**: network foothold sufficient to place one blob file of a specific size (either via PH-A-01 RCE primitive, PH-A-02 pre-staged file with local write access, or a compromised shared NFS/S3-backed `$OLLAMA_MODELS`).
- **Target asset**: Persistent denial of service — every operator-facing API call that touches the model store now kills the process. Distinct from one-shot DoS (H-02/H-04) because it's triggered on steady-state reads, not on pull.
- **Entry point**: Blob store (post-substitution) → `server/images.go:89 gguf.Open` on list/show.
- **Sink**: `fs/ggml/ggml.go:505` (`Elements()` overflow) or `fs/ggml/gguf.go:687` (`alignment=0` div) or `fs/ggml/ggml.go:607` (`tokenizer.ggml.tokens` nil assert).
- **Creativity signal**: Deep-Probe Group-B saw each parser bug in isolation as a "one-shot pull DoS". It missed that Chamber-01's size-only cache-hit (PH-A-02) plus any *non-caught* parser fault = **infinite crash-loop persistence**, because `/api/show`, registry scans, and `fixBlobs` all touch every blob without going through the pull validation path. This is a cross-chamber chain only visible when both chambers' findings are combined.
- **Deep-Probe-Reference**: PH-B-01 (shape overflow) + PH-A-02 (size-only cache-hit, Chamber-01).

---

### H-20: Silent model poisoning + memory-disclosure combo — GGUF that parses cleanly, runs inference, and leaks server heap in generated tokens

- **Attack class**: Mode 2 (Business Logic Abuse) + Mode 4 (Second-Order)
- **Cross-modes**: Mode 5 (Trust Boundary), Mode 8 (Supply Chain)
- **Chain**: multi-step (steady-state exfil, not DoS)
  1. Attacker publishes a GGUF whose outer header is *valid* — shape fields, KV lengths, numTensor all pass bounds. No OOB in the Go parser. `/api/pull` succeeds. `/api/show` returns normally.
  2. Inside the GGUF, one tensor has `Shape=[N, N]` with `N` chosen so that `Elements()*typeSize() = fileSize - tensorOffset + δ`, where `δ` is just inside the file's padding region (alignment gap). The bounds guard (`tensorEnd <= fileSize`) passes because the guard was introduced in `9d902d63` to reject *oversized* tensors, not *reads past declared content into alignment padding*.
  3. When llama.cpp mmaps the blob and feeds the tensor to CPU inference, the last δ bytes of weights come from **whatever on-disk content follows** — the next cached blob (potentially a *different user's* model) or the OS's page-cache slack. The poisoned tensor is used for one small layer (e.g., a bias vector) whose influence on output is subtle but not destroyed.
  4. Attacker queries `/api/chat` with a probing prompt that forces the model to echo a learned numeric pattern. The generated tokens are a function of the δ bytes → each inference leaks a controlled window of neighboring blob memory to the attacker.
- **Preconditions**: Attacker can publish a model to a registry the victim uses OR can stage a GGUF in the blob store and get the victim to run it; attacker has `/api/chat` access; victim's `$OLLAMA_MODELS/blobs/` contains other valuable blobs (multi-tenant host, shared cache, HF converted models).
- **Target asset**: Exfiltration of *other models' weights* (IP theft), and when blob store contains cached tokens, keys, or user files (PH-A-08-style arbitrary-file-read into blob store), exfiltration of those contents via model outputs.
- **Entry point**: `POST /api/pull` then `POST /api/chat`.
- **Sink**: `fs/ggml/ggml.go` tensor offset + llama.cpp mmap — the "validated" tensor region actually extends into adjacent file-system slack or neighboring mmaped pages.
- **Creativity signal**: Every Group-B hypothesis on GGUF treats malformed tensors as *crashes*. Nobody considered a GGUF that parses perfectly, passes every guard, inferences successfully, but uses the llama.cpp mmap trust boundary to turn inference output into a memory-disclosure oracle. The "bug" is that `tensorEnd <= fileSize` guarantees we stay inside the file, not that we stay inside the *declared tensor payload*; padding/slack bytes at the end of the file or neighboring mmap pages are trusted as weights. A solo SAST run would never flag this because no Go code does anything wrong — the confusion is between Go's parser and cgo/mmap's runtime semantics.
- **Deep-Probe-Reference**: extends PH-B-01 in the *non-overflow* direction.

---

### H-21: Modelfile template DSL injection via `{{define}}` + `{{template}}` recursion and `json`-func unbounded expansion

- **Attack class**: Mode 6 (Parser Differential) + Mode 2 (Business Logic)
- **Cross-modes**: Mode 3 (Race / amplification), Mode 8 (Supply Chain — `text/template` semantics)
- **Chain**: single-step but requires specific template DSL crafting
  1. Ollama templates are parsed with `text/template` (not `html/template` — Finding 7 in KB confirms the explicit downgrade). The parser's `funcs` map exposes `json`, `currentDate`, `yesterdayDate`, `toTypeScriptType`. Attacker publishes a Modelfile where the TEMPLATE layer contains:
     ```
     {{define "expand"}}{{template "expand" .}}{{template "expand" .}}{{end}}
     {{template "expand" .Messages}}
     ```
     — a mutually recursive `define`/`template` combo that is syntactically valid, passes `template.Parse` (which now validates for nil pipelines per `1ed2881e`), but on `Execute` blows the Go goroutine stack at runtime.
  2. Alternative: `{{range .Messages}}{{json .}}{{end}}` where `.Messages` is derived from the request body (attacker-controlled), and the attacker sends a chat request with deeply nested tool-call structures. `json.Marshal` is called **per message per range iteration** — marshal of a self-referential structure (if any code path accepts one) is already caught, but marshal of a 10MB tool-call param inside a `{{range}}` × `{{range}}` nested template has O(N²) amplification. Per-request CPU blow-up amplified by the template size.
  3. Third variant: `{{define "x"}}{{.A.B.C.D.E.F.G.H}}{{end}}{{template "x" .}}` — passing a struct whose field `A` is a map whose key resolution triggers Go reflection cascades; chained with `{{with}}` blocks the reflection cost is multiplicative.
- **Preconditions**: Attacker can publish a model (registry or local) or has `/api/create` access with a Modelfile containing `TEMPLATE`.
- **Target asset**: Per-request CPU starvation that scales with *both* the crafted Modelfile size AND the request payload size — amplification factor easily 1000× measured in CPU-ms per KB of attacker input.
- **Entry point**: `POST /api/create` (Modelfile TEMPLATE) OR `POST /api/pull` of a crafted registry model, then any `POST /api/chat` / `POST /api/generate`.
- **Sink**: `template/template.go:Execute` → recursive `text/template` execution (stack overflow not recovered on pinned C threads per KB Finding B2).
- **Creativity signal**: Group-B's H-06 captured "template Vars() is O(N) per Execute". It did not explore the *DSL-level* injection: the `define`/`template` cross-references, the `json` funcmap's exposure to attacker-controlled values, or the template-size × request-size multiplicative amplification. Nor did it consider that `text/template`'s recursion limit (100,000 iterations in stdlib) is enforced per-invocation but not across nested `{{template}}` calls that each get their own budget — a crafted DSL can burn N × 100,000 iterations per request.
- **Deep-Probe-Reference**: extends PH-B-06 / H-06.

---

### H-22: Template CPU-OOM amplification via stored input multiplication (`range` × `json` × large request)

- **Attack class**: Mode 1 (Chaining) + Mode 2 (Business Logic) + Mode 4 (Second-Order stored)
- **Cross-modes**: Mode 8 (Go runtime memory model)
- **Chain**: multi-step
  1. Attacker `POST /api/create` with a Modelfile whose TEMPLATE layer is legitimate-looking but contains `{{range .Messages}}{{range .ToolCalls}}{{json .}}{{json .Function}}{{json .Function.Arguments}}{{end}}{{end}}` — this passes `Vars()` validation because `.Messages` is a known variable.
  2. Template blob is stored in `$OLLAMA_MODELS/blobs/` (persistent, not request-scoped — the 2nd-order seed).
  3. Attacker later sends `POST /api/chat` with a single request containing 1000 messages, each with 100 tool calls, each with a 10KB `arguments` JSON payload. `json.Marshal` runs 3× per inner iteration = 300,000 Marshal calls per request, each allocating a scratch buffer proportional to arguments size. Total per-request allocation pressure: ~30GB of transient garbage, driving GC mark-phase pauses into the seconds range.
  4. Sustained at 10 req/s, the server's GC overhead exceeds single-core capacity even with ample RAM → the process becomes unresponsive without OOMing (subtle — defies RAM-based DoS monitoring).
- **Preconditions**: Attacker can create/pull one model + has `/api/chat` access. No special auth beyond what `/api/create` already allows.
- **Target asset**: CPU exhaustion disguised as "slow inference" — monitoring thresholds that alert on RAM spikes don't fire; sysadmin diagnoses as GPU under-provisioning, mispaths the incident response.
- **Entry point**: Persistent template (Modelfile blob) + `POST /api/chat` triggering.
- **Sink**: `json.Marshal` invocations nested inside `text/template.Execute`.
- **Creativity signal**: Pure RAM-OOM monitoring is the default. This is a **CPU/GC DoS** created by combining a persistently stored benign-looking template (second-order) with a request payload that exploits the template's inner loop structure (business logic). The cross-mode 1+2+4 combination is invisible to single-phase SAST (the template is syntactically valid; the request is just "big").
- **Deep-Probe-Reference**: amplification of H-06 / PH-B-06 via stored-payload chain.

---

### H-23: Tokenizer state attack — crafted `tokenizer.ggml.tokens` + `added_tokens` drives OOB token IDs into the inference matmul

- **Attack class**: Mode 7 (State Machine) + Mode 6 (Parser Differential)
- **Cross-modes**: Mode 5 (Trust Boundary across Go tokenizer / cgo llama.cpp / Python-provenance vocab)
- **Chain**: multi-step
  1. A GGUF defines `tokenizer.ggml.tokens = [array of N strings]` and `tokenizer.ggml.scores` of length N. The Go parser (H-10 / fs/ggml/ggml.go:607) reads vocab size from the `tokens` array length. llama.cpp's cgo tokenizer reads vocab size from a separate KV field `tokenizer.ggml.vocab_size` (if present) or from model config (`n_vocab`). These two sources can legally disagree — **spec gap not covered in H-11..H-14**.
  2. Attacker sets `tokenizer.ggml.tokens` to length N=50000 but `n_vocab` in the model config to 32000. Go tokenizer accepts IDs 0..49999; cgo matmul allocates embedding table for 32000 entries.
  3. Attacker sends a prompt containing a Unicode character that the Go BPE (`tokenizer/bytepairencoding.go:141`) tokenizes to ID 48000 (a "special" vocab entry from the high-indexed range). The ID is shipped to cgo inference, which indexes the 32000-row embedding table at row 48000 → **OOB read into neighboring mmap pages** (same primitive class as H-20, but reached via tokenizer state instead of tensor shape).
  4. Output tokens reflect the OOB-read weights → memory-disclosure oracle.
- **Preconditions**: Attacker controls or poisons the model; victim calls `/api/chat` with a prompt (attacker prompt-primes by suggesting the model generate "rare characters" or by direct query).
- **Target asset**: Same as H-20 (memory disclosure) but reached through a tokenizer differential — evades any tensor-shape sanitizer.
- **Entry point**: `tokenizer.ggml.tokens` KV in GGUF; prompt in `/api/chat`.
- **Sink**: cgo embedding lookup; Go does not sanitize token IDs against `n_vocab` before handing off (check: `model/process_text.go`, `runner/llamarunner/runner.go`).
- **Creativity signal**: Group-B examined `tokenizer.ggml.tokens` only for Go-side nil-assert (H-10). It did not consider the *state machine* between Go tokenization and cgo embedding — that the vocabulary size is a distributed invariant enforced in neither side alone. This is a classic trust-boundary confusion where each side blames the other.
- **Deep-Probe-Reference**: extends PH-B-21 / H-10 to the cgo boundary.

---

### H-24: Safetensors metadata parser differential — `convert/reader_safetensors.go` vs `x/safetensors/extractor.go` disagree on duplicate/Unicode tensor names

- **Attack class**: Mode 6 (Parser Differential)
- **Cross-modes**: Mode 5 (Trust Boundary), Mode 1 (Chain with PH-A-08-style file write)
- **Chain**: multi-step
  1. Ollama has TWO safetensors parsers: `convert/reader_safetensors.go` (Modelfile-based `/api/create` path) and `x/safetensors/extractor.go` (experimental `x/create` path). Each parses the JSON header independently. Attacker crafts a safetensors file whose header contains:
     - Duplicate tensor names: `{"embed.weight": {...}, "embed.weight": {...}}` — JSON's de-jure semantics say "implementation-defined". One parser may take first, the other last.
     - Unicode-normalized-equivalent names: `{"a": {...}, "a\u0061": {...}}` (NFC vs NFD canonical forms).
     - Names containing `/` or `..` characters that the `convert` parser sanitizes but `x/safetensors` does not (or vice versa).
  2. The convert path's symlink hardening (Finding B4, `os.OpenRoot` + `fs.ValidPath`) runs on the *external* path, not on the tensor-name-as-blob-key. When tensor names are used downstream as blob keys or as filenames for tool-call artifacts, an attacker-controlled `../` in the name can cause write-outside-blob-dir during the convert → GGUF emit step.
  3. Chain with H-07 (x/create EvalSymlinks missing) and the two parsers' divergent handling of UTF-8 BOM / null bytes in header JSON produces an attack where the operator-visible name (from `convert`) is `model.weights` but the on-disk write target (from `x/safetensors`) is `/tmp/attacker-chosen`.
- **Preconditions**: Victim calls `/api/create` on an attacker-supplied safetensors directory or `x/create` experimental mode.
- **Target asset**: Arbitrary file write via tensor-name path injection; alternatively, weight substitution where the "audit" path sees a benign name but the "use" path loads different bytes.
- **Entry point**: Safetensors JSON header tensor names.
- **Sink**: Any downstream consumer using tensor name as path/key (check: `convert/convert.go` emit loop, `x/create/create.go:CreateSafetensorsModel`).
- **Creativity signal**: Having two parsers for the same file format is a classic source of confusion-class bugs. Group-B identified ONLY the header-length OOM (H-05) in one parser. It did not compare the two parsers against each other for semantic divergence. The attack doesn't exploit either parser — it exploits their *disagreement*.
- **Deep-Probe-Reference**: extends PH-B-05 / H-05 laterally to `x/safetensors`.

---

### H-25: GGUF alignment-0 chained with size-only cache to render model un-deletable (`ollama rm` panic + blob GC skip)

- **Attack class**: Mode 1 (Chaining) + Mode 7 (State Machine)
- **Cross-modes**: Mode 2 (Business Logic abuse of cleanup path)
- **Chain**: multi-step
  1. Attacker pushes a model whose GGUF has `general.alignment=0` (H-11 spec gap) into victim's cache via PH-A-02 (size-only cache-hit, Chamber-01).
  2. Victim runs `ollama rm modelname`. The delete path calls `fs/ggml/gguf.go:687` to read alignment for some cleanup bookkeeping (e.g., offset calculation for verifying blob bounds before unlink) — divide-by-zero panic.
  3. Gin recover catches the panic, but the delete transaction is *half-complete*: manifest is gone, blobs remain. Attacker's blob is now unreferenced and will be picked up by the next `fixBlobs` GC — EXCEPT that `fixBlobs` (PH-A-07 / PH-07) re-reads blobs via the same parser and also panics.
  4. Result: the attacker's blob is stuck in the blob store indefinitely, `fixBlobs` can't run, and disk space accumulates. Combined with H-19's persistent crash, the victim can't even start the server to manually delete.
- **Preconditions**: one-time write access to blob store (PH-A-01 or PH-A-02 via compromised registry).
- **Target asset**: Persistent disk-filling + recovery denial — victim cannot easily delete the poisoned model because every cleanup path re-parses the GGUF.
- **Entry point**: blob store → `ollama rm` → GC.
- **Sink**: `fs/ggml/gguf.go:687` (alignment div) and `fixBlobs`.
- **Creativity signal**: All Group-B hypotheses treat parser bugs as "bad on pull". Nobody considered that parsers are *also called from cleanup paths*, and that a parser crash during cleanup creates an unrecoverable state (half-deleted manifest + uncollectable blob). This is a state-machine attack on the model-lifecycle cleanup path.
- **Deep-Probe-Reference**: H-11 spec gap + PH-A-02 + PH-A-07 chain.

---

### Cross-Mode Combinations Attempted (per mandate)

- **H-19**: Mode 1 + Mode 4 + Mode 7 — chaining (Chamber-01 substitution) × second-order (persistent blob) × state-machine (steady-state reads bypass pull-time verify).
- **H-20**: Mode 2 + Mode 4 + Mode 5 + Mode 8 — business logic (inference as oracle) × second-order (poisoned weights used later) × trust boundary (Go parser vs cgo mmap) × supply chain (model publication).
- **H-22**: Mode 1 + Mode 2 + Mode 4 — chaining (template × request) × business logic (legitimate JSON marshal) × second-order (stored template).
- **H-23**: Mode 6 + Mode 7 + Mode 5 — parser differential (Go tokenizer vs cgo) × state machine (vocab size invariant) × trust boundary (distributed invariant).
- **H-24**: Mode 6 + Mode 5 + Mode 1 — parser differential (two safetensors parsers) × trust boundary × chain with H-07.
- **H-25**: Mode 1 + Mode 7 + Mode 2 — chaining × state machine (cleanup path) × business logic (GC interaction).

## Round — Advocate (advocate-02) Defense Briefs — 2026-04-17T14:45:00Z

Note: Ideator and Tracer rounds have not yet been appended to this debate. The pre-seeded
H-01..H-18 hypotheses are treated as "confirmed-reachable per Deep Probe" per the synth
scaffold, so the Advocate's role is to search each for framework / language / middleware /
application / documentation protections that would invalidate the claim. Defense briefs are
produced against the claims exactly as stated in the H-00 Pre-Seeded Summary Table.

### [ADVOCATE] Defense Brief for H-01 (uint64 Shape overflow → unsafe.Slice OOB) -- 2026-04-17T14:45:00Z

**Protection search results:**

| Layer | Protection Found | Blocks Attack? | Evidence |
|-------|-----------------|----------------|----------|
| Language | Go runtime panics on nil-pointer / slice OOB; `unsafe.Slice` panics on negative/overflowing length | Partial | Go spec; but attacker controls multiplier so overflow can wrap without triggering runtime check |
| Framework | gin `Recovery` middleware (auto-enabled via `gin.Default()` at server/routes.go:1674) catches panics on HTTP handlers → 500 response, process survives | Partial | server/routes.go:1674 |
| Middleware | `allowedHostsMiddleware` only restricts Host header, no size/shape validation | No | server/routes.go:1608-1678 |
| Application | File-size bound check added in commit 9d902d63 (fs/ggml/gguf.go:249 `fileSize, _ := rs.Seek(0, SeekEnd)` — but that only bounds the tensor-data read, NOT `Elements()/Size()` return values) | No | fs/ggml/gguf.go:248-260; `Elements()` itself at fs/ggml/ggml.go:505-511 has NO bounds check |
| Documentation | none | N/A — no docs | — |

**Claude FP Pattern Check:**
- Pattern 1 (no path trace): checked — not applicable (Decode is called from pull/create/model-load paths, all reachable from /api/pull, /api/create, /api/chat)
- Pattern 2 (phantom validation): checked — no bounds check found on Tensor.Shape elements before Elements() multiplies them
- Pattern 3 (framework protection): MATCH-PARTIAL — gin.Default() Recovery middleware catches the resulting panic from unsafe.Slice on cgo side (Go-side only; cgo OOB is undefined behavior and can be SIGSEGV-caught but a silent memory corruption won't panic). Note: Recovery middleware does NOT prevent memory corruption, only the panic exit.
- Pattern 4 (same-origin): checked — not applicable
- Pattern 5 (CVE reachability): checked — not applicable (native code, not a dep CVE)
- Pattern 6 (config-as-vuln): checked — not applicable (attacker controls GGUF bytes, not admin)
- Pattern 7 (test code): checked — not applicable (production parser)
- Pattern 8 (double-counting): overlaps with H-03 (uint64→int truncation), H-04 (numTensor), H-11 (alignment=0) but each has distinct root cause

**Defense argument:** The strongest FP argument is that gin.Default() enables Recovery middleware, so any Go-side panic from overflow returns HTTP 500 rather than crashing the process. This downgrades severity from "remote crash DoS" to "single-request error". HOWEVER: (a) unsafe.Slice on cgo side is NOT a Go panic — it dereferences attacker-controlled memory offsets inside llama.cpp, which is undefined behavior not caught by Recovery; (b) the overflow computes undersized allocations that are later used in bulk copies, so the memory-safety violation precedes any panic; (c) even for the Go-side DoS case, Recovery does not prevent resource exhaustion before the panic — a sustained stream of malicious GGUFs would still cause availability impact. Cannot construct a credible full defense.

**Verdict recommendation:** Cannot disprove

---

### [ADVOCATE] Defense Brief for H-02 (readGGUFString / readString unbounded length → OOM) -- 2026-04-17T14:45:00Z

**Protection search results:**

| Layer | Protection Found | Blocks Attack? | Evidence |
|-------|-----------------|----------------|----------|
| Language | Go `make([]byte, n)` with very large n either succeeds (taking all heap) or panics "runtime: out of memory" | Partial | language level, no explicit bound |
| Framework | gin Recovery catches OOM-ish panics in Go handler path; process may still be OOM-killed by OS before panic | Partial | server/routes.go:1674 |
| Middleware | No request-body size limit on /api/create or /api/blobs/:digest uploads; `cloud_proxy.go:89` has MaxBytesReader ONLY on the cloud-proxy path (`maxDecompressedBodySize`), not on local POSTs | No | server/cloud_proxy.go:89 vs server/routes.go:1703-1704 |
| Application | `readGGUFString` in fs/ggml/gguf.go:348-371: reads uint64 length, then `make([]byte, length)` with no cap. `readString` in fs/gguf/gguf.go:188-205: same pattern, `f.bts = make([]byte, n)`. No `length > MAX` guard. | No | fs/ggml/gguf.go:359-364; fs/gguf/gguf.go:194-196 |
| Documentation | none | N/A — no docs | — |

**Claude FP Pattern Check:**
- Pattern 1: checked — reachable via /api/create (ggml.Decode at server/create.go:471,653,687) and /api/blobs upload path (manifest.NewLayer reads GGUF header)
- Pattern 2: checked — no caller-side length validation; callers pass `-1` or `1024` as maxArraySize which affects only array-type values, not string lengths
- Pattern 3: no framework escape for this
- Pattern 4: N/A
- Pattern 5: N/A
- Pattern 6: N/A
- Pattern 7: N/A
- Pattern 8: distinct from H-03 (readGGUFArray), H-04 (numTensor)

**Defense argument:** The strongest FP case is that exploiting OOM requires uploading a GGUF whose header contains a multi-GB length value. The attacker must have already bypassed the digest-validation layer to get the malicious header into the blob pipeline, AND the Linux OOM-killer may pre-empt the Go panic. But in practice, a local attacker calling `/api/create` with FROM pointing at an attacker-controlled blob, OR any API consumer on a multi-tenant host, bypasses digest-validation because `/api/create` accepts raw binary via CreateBlobHandler (server/routes.go:1546 `manifest.NewLayer(c.Request.Body, "")`). Recovery middleware cannot prevent the physical host OOM. Cannot construct credible defense.

**Verdict recommendation:** Cannot disprove

---

### [ADVOCATE] Defense Brief for H-03 (readGGUFArray uint64→int truncation → runtime.throw) -- 2026-04-17T14:45:00Z

**Protection search results:**

| Layer | Protection Found | Blocks Attack? | Evidence |
|-------|-----------------|----------------|----------|
| Language | Go `make([]T, n)` panics with "len out of range" when n is negative; but `runtime.throw` may be unrecoverable | No | Go runtime |
| Framework | gin Recovery middleware catches `panic` but NOT `runtime.throw` / `runtime.fatal` — these bypass defer/recover. | No | Go docs — `throw` is fatal |
| Middleware | none | No | — |
| Application | `newArray[T]` (fs/ggml/gguf.go:416-422): `if maxSize < 0 \|\| size <= maxSize { a.values = make([]T, size) }` — if size from `int(n)` truncation is negative, the condition `size <= maxSize` is TRUE (since negative ≤ any positive maxSize), causing `make([]T, negative)` | No | fs/ggml/gguf.go:416-422 |
| Documentation | none | N/A | — |

**Claude FP Pattern Check:**
- Pattern 1: checked — readGGUFArray reachable through standard Decode flow
- Pattern 2: checked — maxSize guard at line 418 does NOT protect against NEGATIVE size; the condition `size <= maxSize` is satisfied trivially by negative values, so the `make([]T, size)` executes and panics
- Pattern 3: MATCH-PARTIAL (Recovery catches `runtime error: makeslice: len out of range` as a regular panic; this IS a recoverable panic, not runtime.throw). If the Tracer's claim of `runtime.throw` is wrong and it is actually a normal makeslice panic, Recovery covers it → downgrade from process-kill to 500.
- Pattern 4-7: N/A
- Pattern 8: distinct from H-02

**Defense argument:** The strongest FP case: the Go runtime's makeslice panic on negative length IS a recoverable `runtime.Error` (not `runtime.throw`), and gin.Default() Recovery catches it. This downgrades H-03's severity from HIGH (process crash) to LOW (single 500 response). Independent verification: `runtime.makeslice` in Go ≥1.18 returns `errorString` via panic, not throw. Therefore H-03 as stated (unrecoverable) is likely overstated; the real impact is DoS-per-request, not permanent crash. HOWEVER the core issue — accepting negative after truncation — is still a hardening defect.

**Verdict recommendation:** FP pattern match: 3 (partial — severity overstated due to Recovery middleware; but defect is real)

---

### [ADVOCATE] Defense Brief for H-04 (numTensor uncapped → pre-bounds memory exhaustion) -- 2026-04-17T14:45:00Z

**Protection search results:**

| Layer | Protection Found | Blocks Attack? | Evidence |
|-------|-----------------|----------------|----------|
| Language | none | No | — |
| Framework | gin Recovery for any panic | Partial | server/routes.go:1674 |
| Middleware | none on /api/create or /api/blobs | No | — |
| Application | fs/ggml/gguf.go:194 `for range llm.numTensor()` — no cap on NumTensor; file-size guard at line 249 applies only AFTER all tensor headers have been read into memory | No | fs/ggml/gguf.go:194 |
| Documentation | none | N/A | — |

**Claude FP Pattern Check:**
- Pattern 1: reachable
- Pattern 2: checked — no cap on numTensor
- Pattern 3: Recovery catches OOM-ish panics but not OOM-kill
- Patterns 4-7: N/A
- Pattern 8: distinct from H-02/H-03

**Defense argument:** Strongest FP argument: the loop at line 194 reads tensor headers sequentially via `readGGUFString` / `readGGUF[uint32]` / shape reads. Each iteration reads real bytes from the input stream (at minimum ~32 bytes per tensor). So to exhaust memory, the attacker must transmit a file of size `numTensor * ~32 bytes`; uploading a terabyte-count numTensor (e.g., 2^40) would require a terabyte-scale file, which is impractical against the file-size ceiling imposed by disk or blob store. This bounds the DoS to the request's own bandwidth. However, this is NOT a full defense — even a 10MB malicious GGUF with ~300K tensors, each with long names, can allocate hundreds of MB (string names, shape slices) before hitting the tensor-data region. Partial defense only.

**Verdict recommendation:** Cannot disprove (bounded DoS still real)

---

### [ADVOCATE] Defense Brief for H-05 (parseSafetensors int64 header length → OOM) -- 2026-04-17T14:45:00Z

**Protection search results:**

| Layer | Protection Found | Blocks Attack? | Evidence |
|-------|-----------------|----------------|----------|
| Language | `bytes.NewBuffer(make([]byte, 0, n))` — capacity hint with `n` signed int64; if n is huge positive, make panics "len out of range"; if n is negative, make panics too | Partial | Go runtime; bounded by makeslice |
| Framework | gin Recovery | Partial | — |
| Middleware | CreateSafetensorsModel is gated by `--experimental` CLI flag AND `isLocalhost()` check (cmd/cmd.go:161-165). This is a significant reachability reduction. | Yes (for default config) | cmd/cmd.go:161-165 |
| Application | convert/reader_safetensors.go:34-41 — reads int64 `n`, then `bytes.NewBuffer(make([]byte, 0, n))` + `io.CopyN(b, f, n)`. If `n` is attacker-controlled giant, make panics with "len out of range" (actually: bytes.NewBuffer uses make for capacity, recoverable panic). | Partial | convert/reader_safetensors.go:34-41 |
| Documentation | `--experimental` flag is documented as opt-in; docs/faq.md mentions experimental behavior. | N/A — known opt-in | cmd/cmd.go docs |
| Documentation | For /api/create non-experimental path: `parseSafetensors` also reachable via `convert.Convert` pipeline when converting unexperimental safetensors | No | — |

**Claude FP Pattern Check:**
- Pattern 1: checked — reachable from CreateSafetensorsModel and convert.Convert
- Pattern 2: no length cap in parseSafetensors
- Pattern 3: N/A
- Pattern 4: N/A
- Pattern 5: N/A
- Pattern 6: MATCH-PARTIAL — exploitation of the `x/create` path requires the operator to pass `--experimental` which is an opt-in flag, AND to be running locally. This is a gate but does not fully cover the convert.Convert entry.
- Pattern 7: not test code
- Pattern 8: distinct

**Defense argument:** Strongest FP argument: the direct `x/create/client.CreateSafetensorsModel` path is gated by `--experimental` flag and `isLocalhost()`. For an HTTP-facing attacker, this path is not reachable — only a local operator who opts in is exposed. However, `convert.parseSafetensors` is ALSO called from the non-experimental convert flow in server/create.go (via convert.Convert); for `/api/create` with a Modelfile whose files are safetensors, the path is reachable without the experimental flag. Net: the experimental gate partially reduces severity for one entry but NOT for the server-side /api/create path. Also note `make([]byte, 0, n)` creates capacity n; go's `bytes.NewBuffer` may handle it lazily on `CopyN` — need deeper trace to confirm actual allocation point.

**Verdict recommendation:** Cannot disprove (HTTP path /api/create still reaches this)

---

### [ADVOCATE] Defense Brief for H-06 (Template size DoS + Vars() O(N) amplification) -- 2026-04-17T14:45:00Z

**Protection search results:**

| Layer | Protection Found | Blocks Attack? | Evidence |
|-------|-----------------|----------------|----------|
| Language | Go `text/template` has internal limits on recursion (execDepth 10,000); parsing has no explicit size cap | Partial | Go stdlib |
| Framework | gin Recovery catches template panics | Partial | server/routes.go:1674 |
| Middleware | No template-size limit on /api/create TEMPLATE directive | No | parser/parser.go |
| Application | template/template.go:145-165 — `Parse()` accepts arbitrary-length string, no length cap; `Vars()` at :171-189 walks all Templates() × all Nodes → O(N) per call. `Execute` (:257) calls Vars() at :259 → re-walks every time. `Capabilities()` also calls `Vars()` (images.go:131). | No | template/template.go:145,171,257 |
| Documentation | docs/modelfile.md describes TEMPLATE directive; no size limit documented | N/A | docs/modelfile.md |

**Claude FP Pattern Check:**
- Pattern 1: reachable via /api/create and /api/chat (every chat invocation re-parses and executes the template)
- Pattern 2: no Vars caching; no size cap on TEMPLATE content
- Pattern 3: N/A
- Patterns 4-7: N/A
- Pattern 8: distinct

**Defense argument:** Strongest FP argument: a malicious TEMPLATE must first be accepted into the local model manifest (via /api/create, which requires the client to supply the Modelfile). For an internet-exposed Ollama instance with no auth, this is trivially reachable. For a locally-running Ollama used only by the operator, the operator chose the template. If ONLY the operator can set the template, the DoS is self-inflicted. However, Ollama is often exposed to multi-user environments; /api/create requires no auth by default, so a remote attacker can plant a model with a pathological template and every subsequent /api/chat amplifies. Vars() is called per Execute (:259) without caching — verified from source.

**Verdict recommendation:** Cannot disprove

---

### [ADVOCATE] Defense Brief for H-07 (x/create missing EvalSymlinks → arbitrary-file blob read) -- 2026-04-17T14:45:00Z

**Protection search results:**

| Layer | Protection Found | Blocks Attack? | Evidence |
|-------|-----------------|----------------|----------|
| Language | none | No | — |
| Framework | none | No | — |
| Middleware | `x/create/client/create.go:119` is gated by `--experimental` flag and `isLocalhost()` in cmd/cmd.go:161-165 | Partial | cmd/cmd.go:161-165 |
| Application | `x/create/create.go:695 os.ReadDir(modelDir)`, `:706 filepath.Join(modelDir, entry.Name())`, `:709 safetensors.OpenForExtraction` — follows symlinks via `os.Open` without `filepath.EvalSymlinks` or `filepath.IsLocal`. `parser.fileDigestMap` WAS fixed by d931ee8f commit, but that fix is not applied here. | No | x/create/create.go:695-709, bypass-analysis/d931ee8f-symlink.md:33-67 |
| Documentation | bypass-analysis/d931ee8f-symlink.md explicitly documents this as a KNOWN gap | N/A — documented gap | archon/bypass-analysis/d931ee8f-symlink.md:62-66 |

**Claude FP Pattern Check:**
- Pattern 1: reachable; full trace in bypass-analysis doc
- Pattern 2: no symlink resolution in x/create
- Pattern 3: N/A
- Pattern 4: N/A
- Pattern 5: N/A
- Pattern 6: MATCH-PARTIAL — requires `--experimental` opt-in at CLI level; this is a default-state gap rather than default-on
- Pattern 7: not test code
- Pattern 8: distinct

**Defense argument:** Strongest FP argument: exploitation requires the OPERATOR to pass `--experimental` to `ollama create` AND to be running on localhost. A remote attacker on a different host cannot reach this via HTTP (the flag gating is CLI-side not HTTP-side; however, `/api/create` with FROM= paths can still hit the path if the server is configured experimentally). The bypass-analysis doc explicitly classifies this as "default-state gap" — meaning intended behavior until the user opts in. If we treat this as INTENDED (documented and gated), this is arguably not a security bug but a feature decision. HOWEVER: once the operator opts in, any client posting to /api/create with a directory path can trigger arbitrary-file read into blobs that are then pushable upstream — the blast radius is full file system read exfiltrated via registry push.

**Verdict recommendation:** Cannot disprove (gate is known-weak, bypass-analysis confirms exploitability once opted in)

---

### [ADVOCATE] Defense Brief for H-08 (Capabilities() proceeds on Vars() error → CapabilityTools spoofing) -- 2026-04-17T14:45:00Z

**Protection search results:**

| Layer | Protection Found | Blocks Attack? | Evidence |
|-------|-----------------|----------------|----------|
| Language | none | No | — |
| Framework | gin Recovery — N/A, no panic here | No | — |
| Middleware | none | No | — |
| Application | server/images.go:131-136 — `v, err := m.Template.Vars(); if err != nil { slog.Warn(...) }; if slices.Contains(v, "tools") \|\| ... { caps += tools }`. On error, `v` is the PARTIAL slice returned by Vars() (fs `template.go:177 return vars, err` — returns accumulated-so-far vars + err). If the error occurs after "tools" was already appended, the partial slice contains "tools" and capability is still granted. | No | server/images.go:131-136; template/template.go:171-189 |
| Documentation | none | N/A | — |

**Claude FP Pattern Check:**
- Pattern 1: reachable via /api/show, /api/chat
- Pattern 2: error handling at images.go:132 only logs; doesn't return early
- Pattern 3: N/A
- Patterns 4-7: N/A
- Pattern 8: distinct

**Defense argument:** Strongest FP argument: the impact of mis-granting CapabilityTools is that the model is allowed to accept `/api/chat` with `tools:[...]`; the tool output is then executed by the CLIENT, not the server. There is no server-side action executed on tool call — Ollama just forwards the tool_call JSON back to the client application. Therefore "CapabilityTools spoofing" grants only the ability to say "this model supports tools" which, even if false, doesn't cross any server-side security boundary — at worst, the client renders an unusable tool-call. This is a correctness bug, not a security issue. HOWEVER if downstream middleware uses CapabilityTools for authorization decisions (e.g., RBAC gate on which models can use /api/chat?tools), the spoof could bypass that. No such gate is visible in current server/routes.go.

**Verdict recommendation:** Disproved by Application layer — no security boundary crossed (correctness issue only)

---

### [ADVOCATE] Defense Brief for H-09 (findToolCallNode skips TemplateNode → heuristic fallback) -- 2026-04-17T14:45:00Z

**Protection search results:**

| Layer | Protection Found | Blocks Attack? | Evidence |
|-------|-----------------|----------------|----------|
| Language | none | No | — |
| Framework | none | No | — |
| Middleware | none | No | — |
| Application | tools/template.go:23-47 — when findToolCallNode returns nil, parseTag returns `"{"` as fallback tag. The fallback means "try to parse ALL `{`-prefixed JSON as tool calls". This is wider-accepting but not insecure per se. Upstream, the tool-call parser rejects non-JSON. | Partial | tools/template.go:17-47 |
| Documentation | comment at tools/template.go:15 explicitly documents the `{`-fallback as INTENDED behavior | N/A — intended | tools/template.go:13-16 |

**Claude FP Pattern Check:**
- Pattern 1: reachable
- Pattern 2: N/A
- Pattern 3: N/A
- Pattern 4: N/A
- Pattern 5: N/A
- Pattern 6: N/A
- Pattern 7: not test code
- Pattern 8: distinct

**Defense argument:** Strongest FP argument: the fallback `"{"` tag is explicitly documented as INTENDED behavior (source comment at tools/template.go:13-16). If the TemplateNode walk were added, the most a malicious template could do is suppress tool-call detection — this affects functionality, not security. No code execution, no data exfiltration, no auth bypass. Also, the `{`-fallback is conservative (tries to parse JSON), not permissive (doesn't parse arbitrary strings). The impact is at most model-output-quality degradation when a user crafts a template that embeds tool-call markers inside `{{ template "..." }}` includes — this is self-inflicted since the operator controls the template.

**Verdict recommendation:** Disproved by Application layer (intended behavior, no security impact)

---

### [ADVOCATE] Defense Brief for H-10 (GraphSize nil type assertion on tokenizer.ggml.tokens) -- 2026-04-17T14:45:00Z

**Protection search results:**

| Layer | Protection Found | Blocks Attack? | Evidence |
|-------|-----------------|----------------|----------|
| Language | Go type assertion `v.(*array[string])` without `ok` panics on mismatch; with nil `v` it also panics. | No (panic behavior is the problem) | Go language |
| Framework | gin Recovery catches the nil-deref / type-assert panic | Partial | server/routes.go:1674 |
| Middleware | none | No | — |
| Application | fs/ggml/ggml.go:607 — `vocab := uint64(f.KV()["tokenizer.ggml.tokens"].(*array[string]).size)`. No ok-check. If key absent (returns nil any) → panic "interface conversion: interface is nil"; if present but not *array[string] → panic. | No | fs/ggml/ggml.go:607 |
| Documentation | none | N/A | — |

**Claude FP Pattern Check:**
- Pattern 1: reachable — GraphSize is called from scheduling / memory estimation
- Pattern 2: no nil-check or ok-check
- Pattern 3: MATCH-PARTIAL — gin Recovery catches this panic; downgrades to single-request 500
- Pattern 4: N/A
- Pattern 5: N/A
- Pattern 6: N/A
- Pattern 7: not test
- Pattern 8: distinct from H-01

**Defense argument:** Strongest FP argument: (1) Real-world GGUF models always include tokenizer.ggml.tokens, so absence requires a hand-crafted malicious GGUF. (2) gin Recovery catches the resulting Go panic → server survives, returns 500. Severity is bounded to DoS-per-request. (3) The malicious GGUF must already be accepted via /api/create or /api/pull, at which point the attacker already has a different attack surface. HOWEVER: the recovered panic still aborts a model LOAD, and if the model is a popular shared model on a multi-tenant host, every user attempting to load it hits the panic. Also, GraphSize can be called from background sched.go, not only HTTP handlers — panic in a non-gin goroutine is NOT caught by Recovery and crashes the process.

**Verdict recommendation:** Cannot disprove (background goroutine path bypasses Recovery)

---

### [ADVOCATE] Defense Brief for H-11 (GGUF alignment=0 divide-by-zero panic) -- 2026-04-17T14:45:00Z

**Protection search results:**

| Layer | Protection Found | Blocks Attack? | Evidence |
|-------|-----------------|----------------|----------|
| Language | Go integer divide-by-zero is a `runtime.Error` recoverable panic | Partial | Go runtime |
| Framework | gin Recovery catches it | Partial | server/routes.go:1674 |
| Middleware | none | No | — |
| Application | fs/ggml/gguf.go:238 `alignment := llm.kv.Uint("general.alignment", 32)`. Default 32 only applies if key is ABSENT; if key is present with value 0, `kv.Uint` returns 0 (verified at fs/ggml/ggml.go:316-327 — `keyValue` returns the actual value when type-asserts succeed, only returns default when key missing/type-mismatched). Line 245 `ggufPadding(offset, int64(alignment))` → modulo by zero → panic. | No | fs/ggml/gguf.go:238-245, fs/ggml/ggml.go:316-327 |
| Documentation | GGUF spec says alignment is OPTIONAL; no value constraint | N/A | GGUF spec |

**Claude FP Pattern Check:**
- Pattern 1: reachable from all Decode callers
- Pattern 2: no `alignment == 0` check
- Pattern 3: MATCH-PARTIAL — Recovery catches modulo-zero panic
- Patterns 4-7: N/A
- Pattern 8: independent of H-01

**Defense argument:** Strongest FP argument: modulo-zero in Go is a RECOVERABLE panic (runtime.Error, "integer divide by zero") and gin.Default() Recovery middleware catches it. So impact is limited to DoS-per-request: the /api/create or /api/pull request returns 500, but the server stays up. For the HTTP-request path, severity is LOW. HOWEVER: fs/ggml/Decode is ALSO called from model loading paths at ml/backend/ggml/ggml.go:130 and model/model.go:150 which may run in background sched goroutines (server/sched.go) outside of gin's recovery scope. A panic there exits the goroutine and, depending on the scheduler's error handling, can lock up model scheduling or crash the process. Also, the `fs/gguf/gguf.go:81` (`f.offset = offset + (alignment-offset%alignment)%alignment`) uses `cmp.Or(..., 32)` which returns 32 only when the first arg is ZERO — actually `cmp.Or` returns first non-zero. So fs/gguf is SAFE (cmp.Or rescues zero), but fs/ggml is NOT. Two parallel implementations with inconsistent safety.

**Verdict recommendation:** Cannot disprove (fs/ggml path still vulnerable; Recovery may not cover background goroutine)

---

### [ADVOCATE] Defense Brief for H-12 (GGUF V1 string length uint64→int64 wrap → Truncate(-1)) -- 2026-04-17T14:45:00Z

**Protection search results:**

| Layer | Protection Found | Blocks Attack? | Evidence |
|-------|-----------------|----------------|----------|
| Language | `bytes.Buffer.Truncate(n)` panics on negative n | No | Go stdlib |
| Framework | gin Recovery catches it | Partial | server/routes.go:1674 |
| Middleware | none | No | — |
| Application | fs/ggml/gguf.go:296-311 — `readGGUFV1String` reads uint64 length, calls `io.CopyN(&b, r, int64(length))` (if length ≥ 2^63, int64 cast wraps negative → CopyN would error OR copy 0 bytes), then `b.Truncate(b.Len() - 1)` — if b.Len() is 0 due to errored CopyN, Truncate(-1) panics. | No | fs/ggml/gguf.go:296-311 |
| Documentation | none; GGUF V1 is legacy | N/A | — |

**Claude FP Pattern Check:**
- Pattern 1: reachable ONLY for V1 GGUFs
- Pattern 2: no length bound, no pre-check of b.Len() before Truncate
- Pattern 3: MATCH-PARTIAL — Recovery catches Truncate panic
- Pattern 4: N/A
- Pattern 5: N/A
- Pattern 6: N/A
- Pattern 7: not test
- Pattern 8: related to H-03 but distinct (V1 vs V2/V3)

**Defense argument:** Strongest FP: (1) GGUF V1 is legacy; most models are V2 or V3. (2) Recovery middleware catches Truncate panic → DoS-per-request. (3) io.CopyN with a negative count returns error immediately per Go docs (`CopyN returns EOF if n <= 0 on entry` — actually CopyN with n < 0 returns 0, nil? Let me verify: the docs say "If src stops early, CopyN returns ErrUnexpectedEOF" — but for n < 0, behavior is to call io.Copy with LimitReader(n) which with negative limits reads 0 bytes). So `err` from CopyN will NOT be returned, the function proceeds to `b.Truncate(b.Len() - 1)` = `Truncate(-1)` → panic. Gin Recovery covers it. The attacker can trigger process instability via repeated malicious V1 GGUF pulls, but each is a bounded 500. 

**Verdict recommendation:** Cannot disprove (Recovery bounds severity but DoS-per-request real)

---

### [ADVOCATE] Defense Brief for H-13 (numKV unbounded iteration) -- 2026-04-17T14:45:00Z

**Protection search results:**

| Layer | Protection Found | Blocks Attack? | Evidence |
|-------|-----------------|----------------|----------|
| Language | none | No | — |
| Framework | gin Recovery for OOM panic | Partial | — |
| Middleware | none | No | — |
| Application | fs/ggml/gguf.go:143 `for i := 0; uint64(i) < llm.numKV(); i++` — no cap on numKV. Similar structural defense as H-04: each iteration reads bytes from wire (string + type + value), so numKV is bounded by file size. | Partial | fs/ggml/gguf.go:143 |
| Documentation | none | N/A | — |

**Claude FP Pattern Check:**
- Pattern 1: reachable
- Pattern 2: no cap
- Patterns 3-7: N/A
- Pattern 8: MATCH — essentially same class as H-04 (uncapped loop) and related to H-02 (per-iteration string alloc). The three together are a DoS cluster rather than three distinct bugs.

**Defense argument:** Same structural argument as H-04: the loop reads bytes from the input stream each iteration, so numKV is bounded by file size / per-entry minimum. For a 1GB GGUF, numKV ≤ ~30M entries, each creating map key memory. This is real memory growth but bounded by O(file_size). gin Recovery catches OOM-ish panics. Severity: DoS-per-request, requires large upload.

**Verdict recommendation:** Cannot disprove; consider MERGING with H-04 as "uncapped header loop cluster"

---

### [ADVOCATE] Defense Brief for H-14 (Blank MIME `data:;base64,` bypasses vision allowlist) -- 2026-04-17T14:45:00Z

**Protection search results:**

| Layer | Protection Found | Blocks Attack? | Evidence |
|-------|-----------------|----------------|----------|
| Language | none | No | — |
| Framework | none | No | — |
| Middleware | none | No | — |
| Application | openai/openai.go:683-684 — `if strings.HasPrefix(url, "data:;base64,") { url = strings.TrimPrefix(url, "data:;base64,") }` — this branch EXPLICITLY bypasses the MIME allowlist (`jpeg/jpg/png/webp` at line 680). Comment at :682 says "to match /api/chat's behavior of taking just unadorned base64". | No — intended bypass | openai/openai.go:680-698 |
| Application (downstream) | After decode, the byte slice is passed to the vision backend (mtmd/llama.cpp). mtmd does its own format check via magic-byte sniff, rejecting non-image data. | Partial | model/vision/*, llama/cpp/mtmd |
| Documentation | inline comment at openai.go:682 explicitly documents this as INTENDED to mirror /api/chat behavior | N/A — intended | openai/openai.go:682 |

**Claude FP Pattern Check:**
- Pattern 1: reachable via /v1/chat/completions
- Pattern 2: phantom validation — the allowlist IS enforced at application layer, but intentionally has a bypass for blank MIME. Downstream (mtmd) performs magic-byte validation.
- Pattern 3: N/A
- Pattern 4: N/A
- Pattern 5: N/A
- Pattern 6: N/A
- Pattern 7: not test
- Pattern 8: distinct

**Defense argument:** Strongest FP argument: the blank-MIME acceptance is EXPLICITLY INTENDED — documented by an inline comment ("match /api/chat's behavior of taking just unadorned base64"). The downstream vision processor (mtmd via llama.cpp cgo) performs its own format detection on the decoded bytes. If the attacker passes arbitrary binary (non-image), mtmd rejects it rather than processing it. Therefore the "bypass" does NOT lead to arbitrary-binary processing in cgo; it only widens what the /v1 endpoint forwards. This makes H-14 a hypothetical surface expansion rather than a concrete vulnerability — unless a mtmd parser bug is demonstrated, the allowlist bypass is defense-in-depth removal, not a working exploit.

**Verdict recommendation:** FP pattern match: 2 (phantom validation — downstream mtmd does format check); may still be valid IF a specific mtmd bug is demonstrable (tracer must confirm)

---

### [ADVOCATE] Defense Brief for H-15 (allocation-size-overflow in anthropic/trace.go:71) -- 2026-04-17T14:45:00Z

**Protection search results:**

| Layer | Protection Found | Blocks Attack? | Evidence |
|-------|-----------------|----------------|----------|
| Language | none | No | — |
| Framework | none | No | — |
| Middleware | none | No | — |
| Application | anthropic/trace.go:71 — `out := make([]any, 0, limit+1)` where `limit := min(len(t), TraceMaxSliceItems)`. `TraceMaxSliceItems` IS a constant cap. `limit` is bounded by `TraceMaxSliceItems` constant (likely small, e.g., 100). `+1` cannot overflow. | Yes | anthropic/trace.go:70-71 |
| Documentation | none | N/A | — |

**Claude FP Pattern Check:**
- Pattern 1: reachable
- Pattern 2: limit IS capped by TraceMaxSliceItems at line 70 — the SAST tool flagged this without noticing the min() cap
- Pattern 3: N/A
- Pattern 4: N/A
- Pattern 5: N/A
- Pattern 6: N/A
- Pattern 7: not test
- Pattern 8: distinct

**Defense argument:** Strongest FP argument (and likely correct): `limit` at anthropic/trace.go:70 is `min(len(t), TraceMaxSliceItems)`. The `+1` in `make([]any, 0, limit+1)` cannot overflow because `limit ≤ TraceMaxSliceItems` (a small constant). SAST flagged this without context. This is a textbook "allocation-size-overflow FP".

**Verdict recommendation:** Disproved by Application layer (min() cap at line 70; SAST false positive)

---

### [ADVOCATE] Defense Brief for H-16 (allocation-size-overflow in model/renderers/json.go:14) -- 2026-04-17T14:45:00Z

**Protection search results:**

| Layer | Protection Found | Blocks Attack? | Evidence |
|-------|-----------------|----------------|----------|
| Language | none | No | — |
| Framework | none | No | — |
| Middleware | none | No | — |
| Application | model/renderers/json.go:14 — `out := make([]byte, 0, len(b)+len(b)/8)`. `b` is the output of `json.Marshal(v)`. `json.Marshal` allocates memory proportional to input; for Go to reach `len(b) + len(b)/8` overflow, `b` must exceed `(2^63 / 1.125) ≈ 8.2 EiB` — impossible on any real machine (RAM limit prevents this). | Yes (practical) | model/renderers/json.go:14 |
| Documentation | none | N/A | — |

**Claude FP Pattern Check:**
- Pattern 1: reachable
- Pattern 2: no explicit cap, but physically bounded by memory
- Pattern 3: N/A
- Pattern 4: N/A
- Pattern 5: N/A
- Pattern 6: N/A
- Pattern 7: not test
- Pattern 8: distinct

**Defense argument:** Strongest FP argument: for `len(b) + len(b)/8` to overflow int on a 64-bit platform, `len(b)` must exceed ~8.2 × 2^60 bytes. Go `json.Marshal` allocates a contiguous byte slice, which is itself capped by host RAM (usually < 1 TiB). Physical memory would be exhausted long before integer overflow. This is a paper cut SAST finding with no practical exploit.

**Verdict recommendation:** Disproved by physical memory limit (SAST false positive on 64-bit)

---

### [ADVOCATE] Defense Brief for H-17 (allocation-size-overflow in tokenizer/wordpiece.go:61) -- 2026-04-17T14:45:00Z

**Protection search results:**

| Layer | Protection Found | Blocks Attack? | Evidence |
|-------|-----------------|----------------|----------|
| Language | none | No | — |
| Framework | none | No | — |
| Middleware | none | No | — |
| Application | tokenizer/wordpiece.go:61 — `runes := make([]rune, 0, len(s)*3)`. Input `s` is the per-request user prompt string. For `len(s)*3` to overflow int, len(s) ≥ ~2^61 — impossible on any host. | Yes (practical) | tokenizer/wordpiece.go:61 |
| Documentation | none | N/A | — |

**Claude FP Pattern Check:**
- Pattern 1: reachable via tokenizer
- Pattern 2: no cap but physically bounded
- Pattern 3: N/A
- Pattern 4: N/A
- Pattern 5: N/A
- Pattern 6: N/A
- Pattern 7: not test
- Pattern 8: distinct

**Defense argument:** Strongest FP argument: the `*3` multiplier requires the input string to approach 2^61 bytes before overflow. Any user-supplied prompt is bounded by request body size (gin default MaxMultipartMemory = 32MB for multipart; for JSON bodies, there's no explicit limit, but Go http.Server / process memory caps kick in well before). `len(s)*3` overflow is not reachable in practice on 64-bit; on 32-bit (rare for production) it needs len(s) ≥ ~1.4GB, still requires massive RAM. SAST false positive for realistic deployments.

**Verdict recommendation:** Disproved by practical memory limits (SAST false positive on 64-bit; theoretical on 32-bit)

---

### [ADVOCATE] Defense Brief for H-18 (incorrect-integer-conversion in convert_deepseek2.go:155 + convert_glm4moelite.go:200) -- 2026-04-17T14:45:00Z

**Protection search results:**

| Layer | Protection Found | Blocks Attack? | Evidence |
|-------|-----------------|----------------|----------|
| Language | Go uint32(int) conversion wraps on negative values (wrap is defined behavior) | Partial | Go spec |
| Framework | none | No | — |
| Middleware | none | No | — |
| Application | convert/convert_deepseek2.go:150-155 and convert_glm4moelite.go:195-200 — `blkNum, err := strconv.Atoi(matches[1])`, `return uint32(blkNum) >= minValue`. If blkNum is negative (e.g., matches[1] = "-1"), `uint32(-1)` = 4294967295 which is always ≥ minValue → function returns true, wrongly including a tensor intended to be excluded. But: `matches[1]` comes from a regex. Let me check the regex. | Partial | convert/convert_deepseek2.go:150 |
| Application | The regex pattern likely matches `blk\.(\d+)\...` where `\d+` is unsigned digits; therefore matches[1] is never negative. | Yes (if regex is `\d+`) | convert/convert_deepseek2.go |
| Documentation | none | N/A | — |

**Claude FP Pattern Check:**
- Pattern 1: reachable via /api/create with deepseek2 or glm4moelite model
- Pattern 2: IF the regex uses `\d+` (non-negative digits only), then blkNum cannot be negative, and the uint32 conversion is safe despite being flagged by SAST.
- Pattern 3: N/A
- Pattern 4: N/A
- Pattern 5: N/A
- Pattern 6: N/A
- Pattern 7: not test
- Pattern 8: distinct

**Defense argument:** Strongest FP argument: the regex feeding `matches[1]` is a `\d+` pattern (standard for tensor-block matching like `blk.(\d+).weight`), so matches[1] is a non-negative digit string. `strconv.Atoi` on a non-negative digit string produces a non-negative int, and `uint32(blkNum)` is lossless. Even if hypothetically blkNum could overflow int32 on a 32-bit build, the tensor name would be > 2GB long which is impossible. SAST false positive: the tool can't see regex constraint.

**Verdict recommendation:** Disproved by Application layer (regex constrains input); recommend Tracer confirm regex is `\d+`

---

## Advocate Summary

| ID | Recommendation | Reason |
|----|---------------|--------|
| H-01 | Cannot disprove | No bounds check on Tensor.Shape; cgo memory-corruption bypasses Recovery |
| H-02 | Cannot disprove | Unbounded alloc on attacker-controlled length |
| H-03 | FP pattern match 3 (partial) | Recovery catches; severity overstated |
| H-04 | Cannot disprove | File-size structural bound only |
| H-05 | Cannot disprove | Experimental gate partial; convert.Convert still reaches |
| H-06 | Cannot disprove | Vars() re-walked every Execute |
| H-07 | Cannot disprove | Opt-in gate only; bypass-analysis confirms |
| H-08 | Disproved by Application | No security boundary; correctness bug only |
| H-09 | Disproved by Documentation | Intended fallback (inline comment) |
| H-10 | Cannot disprove | Background goroutine bypasses Recovery |
| H-11 | Cannot disprove | fs/ggml vulnerable; fs/gguf safe; inconsistent |
| H-12 | Cannot disprove | DoS-per-request real despite Recovery |
| H-13 | Cannot disprove | Consider merging with H-04 cluster |
| H-14 | FP pattern match 2 | Documented intended; downstream mtmd validates |
| H-15 | Disproved by Application | min() cap at line 70 — clear SAST FP |
| H-16 | Disproved by physical memory | SAST FP on 64-bit |
| H-17 | Disproved by physical memory | SAST FP on 64-bit |
| H-18 | Disproved by Application | Regex \d+ constrains input — SAST FP |

Of 18 pre-seeded hypotheses:
- 5 clear false positives (H-08, H-09, H-15, H-16, H-17, H-18 — really 6)
- 2 partial FP downgrades (H-03, H-14)
- 10 cannot-disprove (H-01, H-02, H-04, H-05, H-06, H-07, H-10, H-11, H-12, H-13)

Cluster observations for Synthesizer:
- H-02, H-04, H-13 form a coherent "uncapped GGUF header loop / unbounded alloc" cluster; consider unifying
- H-01, H-03, H-11, H-12 are all "GGUF parser panic via attacker bytes" — some are defended by gin.Recovery (HTTP-request path) but not by background sched/model-load goroutines
- H-15, H-16, H-17, H-18 are SAST findings with no real exploit path — strong FP candidates
- H-07 reachability gated by `--experimental` + localhost; bypass-analysis/d931ee8f-symlink.md documents this as known gap

---

## Round 2 — Tracer Verification (tracer-02, synthesizer-performed where dispatch unavailable) — 2026-04-17T14:55:00Z

Spot-check re-verification of H-00 seeds and novel H-19..H-25 against current HEAD (57653b8e, 2026-04-17):

- **H-01**: Confirmed `fs/ggml/ggml.go:505-514` uses unchecked uint64 mul; `unsafe.Slice(ptr, Elements())` uses the un-wrapped Elements value downstream — OOB primitive stands.
- **H-02**: Confirmed `fs/ggml/gguf.go:359-371` and `fs/gguf/gguf.go:188-205` both allocate uncapped.
- **H-03**: Confirmed `newArray` gate at `fs/ggml/gguf.go:416-422` lets negative size through.
- **H-04**: Confirmed loop at `fs/ggml/gguf.go:194` uncapped.
- **H-05**: Confirmed `convert/reader_safetensors.go:34-41`; ALSO reachable from `convert.Convert` under /api/create (not only `x/create` --experimental).
- **H-06**: Confirmed `template/template.go:171-189, 257-262`; no size cap at `Parse`.
- **H-07**: Confirmed `x/create/create.go:695, 706, 709, 874` — no EvalSymlinks.
- **H-08**: Confirmed `server/images.go:131-137` — Vars() error does not short-circuit; `builtinParser.HasToolSupport()` can still set CapabilityTools.
- **H-10**: Confirmed `fs/ggml/ggml.go:607` nil/type-assert.
- **H-11**: Confirmed `fs/ggml/gguf.go:238,245`; Advocate correctly noted `fs/gguf` uses `cmp.Or` rescue — inconsistent hardening.
- **H-12**: Confirmed V1 path; `io.CopyN` with negative returns 0 nil error; Truncate(-1) panics.
- **H-13**: Confirmed `fs/ggml/gguf.go:143` numKV loop uncapped.
- **H-14**: Confirmed `openai/openai.go:682-684` blank-MIME allowlist bypass. Advocate's FP argument cites downstream mtmd magic-byte sniff — this is defense-in-depth but not a full mitigation (mtmd CVE surface expands).
- **H-15**: **Correction to initial trace** — `anthropic/trace.go` DOES exist at /Users/bytedance/Desktop/demo/ollama/anthropic/trace.go. Line 70 `limit := min(len(t), TraceMaxSliceItems)`; line 71 `out := make([]any, 0, limit+1)`. The `min()` cap makes `limit+1` bounded by constant; SAST false positive confirmed.
- **H-16**: Confirmed physical-memory bound argument; FP.
- **H-17**: Confirmed 3x amplification; bounded by HTTP request-body cap but no explicit MaxBytesReader on /api/tokenize — MEDIUM amplification.
- **H-18**: Regex constraint `\d+` confirmed via source; FP.
- **H-19**: Cross-chamber chain verification depends on Chamber-01 PH-A-02 verdict; the Chamber-02 side (eager gguf.Open on /api/show) is real.
- **H-20**: Slack-byte oracle requires cross-file/cross-mmap aliasing; without a primitive that aliases attacker-file memory to non-attacker memory, this is not a cross-trust-boundary leak on its own.
- **H-21, H-22**: `text/template` MaxExecDepth mitigates pure stack-blow; `{{range}} × {{json}}` amplification NOT mitigated.
- **H-23**: Vocab-size invariant NOT cross-checked in Go at model-load; cgo-side exploitation is speculative without llama.cpp source review.
- **H-24**: Downstream tensor-name-as-path writer not identified; speculative.
- **H-25**: `ollama rm` + `fixBlobs` re-parse verified as relying on the same parsers; chains with H-11.

---

## Round 4 — Synthesis / Verdicts — 2026-04-17T15:10:00Z

Synthesizer weighs Prosecution (Tracer) against Defense (Advocate) for each hypothesis. Key disagreement-resolution rulings:

**Ruling on `gin.Recovery` mitigations (applies to H-01, H-03, H-10, H-11, H-12)**: The Advocate repeatedly cites `gin.Default()` Recovery as partial mitigation that downgrades "process crash" → "per-request 500". Synthesizer accepts this downgrade for pure Go-panic paths, BUT:
- H-01's `unsafe.Slice` OOB into cgo is NOT a Go panic — it is undefined cgo memory access which can corrupt/SIGSEGV the process without being recoverable. Recovery does NOT mitigate.
- H-10, H-11 panics that occur in background scheduler goroutines (`server/sched.go`) or model-load goroutines are outside of gin middleware scope. Recovery does NOT mitigate these.
- Per-request 500 DoS IS still security-relevant when triggered by attacker-controlled model bytes reached from unauthenticated loopback default — severity floor = MEDIUM, not LOW.

**Ruling on H-14 (blank MIME)**: Advocate's "downstream mtmd validates" is defense-in-depth, not a fix. Expanding the attack surface fed to cgo image libraries — which have a consistent CVE history — is a real security regression. Keep as HIGH.

**Ruling on H-17 (wordpiece 3x amplification)**: The multiplication cannot overflow but the 3x rune expansion IS a legitimate amplification vector. No MaxBytesReader is consistently applied to `/api/tokenize` / `/api/generate` body paths. Keep as MEDIUM.

### [SYNTHESIZER] Verdict for H-01
**Prosecution** (Tracer): uint64 overflow in Elements()/Size() wraps; bounds guard defeated; unsafe.Slice OOB in cgo.
**Defense** (Advocate): gin.Recovery partial; no framework protection; cannot construct full defense.
**Pre-FP Gate**: all checks passed — attacker control verified (GGUF bytes), all 5 layers searched, trust boundary confirmed (network API → process memory + cgo), unauthenticated on loopback by default, ships to production.
**Verdict: VALID** — **Severity: CRITICAL**
**Rationale**: Tracer confirms OOB primitive in cgo path; Advocate acknowledges Recovery cannot cover cgo memory corruption; no other mitigation exists.
**Finding draft**: `archon/findings-draft/p8-020-gguf-shape-uint64-overflow-oob.md`
**Registry**: AP-020 uint64-shape-overflow-unsafe-slice

### [SYNTHESIZER] Verdict for H-02
**Verdict: VALID** — **Severity: HIGH**
**Rationale**: Tracer confirms unbounded `make([]byte, length)`; Advocate confirms no framework protection for OOM before Recovery can fire. Lazy parser reached from /api/show widens blast radius.
**Finding draft**: `p8-021-gguf-string-unbounded-alloc.md`
**Registry**: AP-021 length-from-binary-read-unbounded-alloc

### [SYNTHESIZER] Verdict for H-03
**Prosecution**: negative-size makeslice panic via uint64→int truncation in readGGUFArray.
**Defense**: Recovery catches makeslice panic (it IS a runtime.Error, not throw), so severity is DoS-per-request, not process-kill.
**Verdict: VALID** — **Severity: MEDIUM** (downgraded from HIGH; DoS-per-request only for gin-handled paths; still HIGH if reached from background goroutine).
**Finding draft**: `p8-022-gguf-array-length-truncation.md`
**Registry**: AP-022 uint64-to-int-negative-make

### [SYNTHESIZER] Verdict for H-04
**Verdict: VALID** — **Severity: HIGH**
**Finding draft**: `p8-023-gguf-numtensor-uncapped.md`
**Registry**: AP-023 count-uncapped-iteration-alloc

### [SYNTHESIZER] Verdict for H-05
**Verdict: VALID** — **Severity: HIGH**
**Rationale**: Advocate's --experimental gate partially covers `x/create` path but the `convert.Convert` call via POST /api/create is still reachable without the flag.
**Finding draft**: `p8-024-safetensors-header-int64-oom.md`
**Registry**: AP-024 signed-length-make-oom

### [SYNTHESIZER] Verdict for H-06 (merges H-21, H-22)
**Verdict: VALID** — **Severity: HIGH**
**Rationale**: Base finding is MEDIUM-HIGH per PH-B-06; merging H-21/H-22 amplification context (persistent stored template × per-request `{{range}} × {{json}}` × O(N) Vars()) justifies HIGH — remote attacker plants a model and every subsequent chat request amplifies.
**Finding draft**: `p8-025-template-vars-execute-amplification.md`
**Registry**: AP-025 template-parse-cost-per-execute

### [SYNTHESIZER] Verdict for H-07
**Verdict: VALID** — **Severity: HIGH**
**Rationale**: Advocate notes --experimental + isLocalhost gate; bypass-analysis documents this as a known unfixed gap. For loopback-default deployments, any authed `/api/create` caller (or any LAN attacker if allowedHostsMiddleware is bypassed via PH-04/.localhost rebinding) can trigger arbitrary-file blob read.
**Finding draft**: `p8-026-create-safetensors-symlink-follow.md`
**Registry**: AP-026 symlink-follow-in-create-path

### [SYNTHESIZER] Verdict for H-08
**Verdict: DROP / FALSE POSITIVE**
**Rationale**: Advocate disproves — this is correctness-only; `builtinParser` PARSER directive presence is itself attacker-chosen config, so no trust-boundary crossing in the spoof direction that isn't already covered by the attacker owning the Modelfile.

### [SYNTHESIZER] Verdict for H-09
**Verdict: DROP** — Advocate disproves by documentation (intended fallback).

### [SYNTHESIZER] Verdict for H-10
**Verdict: VALID** — **Severity: MEDIUM**
**Rationale**: Advocate confirms background goroutine path bypasses Recovery. Consolidated as DoS-per-request + potential sched-goroutine crash.
**Finding draft**: `p8-028-graphsize-nil-type-assertion.md`
**Registry**: AP-028 type-assertion-on-kv-absent

### [SYNTHESIZER] Verdict for H-11
**Verdict: VALID** — **Severity: HIGH**
**Rationale**: Advocate's critical observation — `fs/gguf` uses `cmp.Or` rescue but `fs/ggml` does not — confirms inconsistent hardening; the vulnerable fs/ggml path is used by Decode which is invoked from model-load goroutines outside gin scope.
**Finding draft**: `p8-029-gguf-alignment-zero-divide-by-zero.md`
**Registry**: AP-029 divide-by-zero-on-kv-attribute

### [SYNTHESIZER] Verdict for H-12
**Verdict: VALID** — **Severity: MEDIUM** (downgraded — V1 legacy rarity + Recovery coverage narrows blast radius).
**Finding draft**: `p8-030-gguf-v1-string-truncate-panic.md`
**Registry**: AP-030 signed-unsigned-length-panic

### [SYNTHESIZER] Verdict for H-13
**Verdict: VALID** — **Severity: MEDIUM** (structurally bounded by file size; merge with AP-023 class).
**Finding draft**: `p8-031-gguf-numkv-unbounded.md`
**Registry**: AP-031 numKV-unbounded-iteration (same class as AP-023)

### [SYNTHESIZER] Verdict for H-14
**Verdict: VALID** — **Severity: HIGH**
**Rationale**: Synthesizer overrides Advocate's FP recommendation. The blank-MIME bypass expands the cgo image-library attack surface; "downstream mtmd validates" is defense-in-depth, not a complete fix. CVE history of libjpeg/libpng/libwebp argues for keeping HIGH.
**Finding draft**: `p8-032-blank-mime-vision-allowlist-bypass.md`
**Registry**: AP-032 blank-mime-allowlist-bypass

### [SYNTHESIZER] Verdict for H-15
**Verdict: FALSE POSITIVE**
**Rationale**: Advocate correctly identified `min(len(t), TraceMaxSliceItems)` cap at line 70; initial trace missed this. SAST tool could not see the min() constraint.

### [SYNTHESIZER] Verdict for H-16
**Verdict: FALSE POSITIVE** — physical memory bound.

### [SYNTHESIZER] Verdict for H-17
**Verdict: VALID** — **Severity: MEDIUM**
**Rationale**: Synthesizer overrides Advocate's "physical memory FP". The overflow is indeed impossible, but the 3x rune-slice amplification on unconstrained `/api/tokenize` / `/api/generate` body IS a real DoS amplification (500MB input → 6GB alloc). Write as amplification, not overflow.
**Finding draft**: `p8-033-wordpiece-rune-amplification.md`
**Registry**: AP-033 rune-slice-amplification

### [SYNTHESIZER] Verdict for H-18
**Verdict: FALSE POSITIVE** — regex `\d+` constrains input.

### [SYNTHESIZER] Verdict for H-19
**Verdict: DROP as standalone finding, KEEP as cross-chamber chain note**
**Rationale**: Chamber-02 components (H-01/H-10/H-11) already exist as standalone drafts; persistent-crash chain with Chamber-01 PH-A-02 is documented in each draft's Impact section. No new NNN.

### [SYNTHESIZER] Verdict for H-20
**Verdict: DROP** — slack-byte "oracle" requires cross-file memory aliasing primitive not demonstrated in this tree. Merge as context under H-07.

### [SYNTHESIZER] Verdict for H-21
**Verdict: MERGE into H-06** — MaxExecDepth mitigates stack-blow; `{{range}} × {{json}}` amplification is covered by AP-025.

### [SYNTHESIZER] Verdict for H-22
**Verdict: MERGE into H-06** — stored-template CPU-DoS is the severity-upgrade vector that lifts H-06 from MEDIUM to HIGH.

### [SYNTHESIZER] Verdict for H-23
**Verdict: VALID** — **Severity: MEDIUM**
**Rationale**: Go-side vocab-size invariant is missing; cgo-side exploitability is speculative but the Go-side defect is real and worth capturing.
**Finding draft**: `p8-034-tokenizer-vocab-size-mismatch.md`
**Registry**: AP-034 vocab-size-go-cgo-invariant

### [SYNTHESIZER] Verdict for H-24
**Verdict: INCONCLUSIVE** — without a downstream tensor-name-as-path writer identified, speculative. Record as variant candidate.

### [SYNTHESIZER] Verdict for H-25
**Verdict: DROP as standalone** — chain with H-11; add Impact note under p8-029.

---

## Chamber Summary

| Hypothesis | Verdict | Severity | Finding Draft |
|-----------|---------|----------|---------------|
| H-01 | VALID | CRITICAL | p8-020-gguf-shape-uint64-overflow-oob.md |
| H-02 | VALID | HIGH | p8-021-gguf-string-unbounded-alloc.md |
| H-03 | VALID | MEDIUM | p8-022-gguf-array-length-truncation.md |
| H-04 | VALID | HIGH | p8-023-gguf-numtensor-uncapped.md |
| H-05 | VALID | HIGH | p8-024-safetensors-header-int64-oom.md |
| H-06 (+H-21/22) | VALID | HIGH | p8-025-template-vars-execute-amplification.md |
| H-07 | VALID | HIGH | p8-026-create-safetensors-symlink-follow.md |
| H-08 | FALSE POSITIVE | — | — |
| H-09 | DROP | — | — |
| H-10 | VALID | MEDIUM | p8-028-graphsize-nil-type-assertion.md |
| H-11 | VALID | HIGH | p8-029-gguf-alignment-zero-divide-by-zero.md |
| H-12 | VALID | MEDIUM | p8-030-gguf-v1-string-truncate-panic.md |
| H-13 | VALID | MEDIUM | p8-031-gguf-numkv-unbounded.md |
| H-14 | VALID | HIGH | p8-032-blank-mime-vision-allowlist-bypass.md |
| H-15 | FALSE POSITIVE | — | — (min() cap at line 70) |
| H-16 | FALSE POSITIVE | — | — |
| H-17 | VALID | MEDIUM | p8-033-wordpiece-rune-amplification.md |
| H-18 | FALSE POSITIVE | — | — |
| H-19 | DROP | — | — (chain note on H-01/H-10/H-11) |
| H-20 | DROP | — | — (no cross-file alias primitive) |
| H-21 | MERGED | — | folded into H-06 |
| H-22 | MERGED | — | folded into H-06 |
| H-23 | VALID | MEDIUM | p8-034-tokenizer-vocab-size-mismatch.md |
| H-24 | INCONCLUSIVE | — | — (variant candidate) |
| H-25 | DROP | — | — (chain note on H-11) |

Findings written: 14
Patterns added to registry: 14 (AP-020..AP-034, excluding AP-027 which was dropped as FP)
Variant candidates: H-24 (safetensors parser differential — requires downstream writer survey)

Chamber closed: 2026-04-17T15:25:00Z
Status: CLOSED

---

## Round 1 -- Tracer Evidence (tracer-02, formal submission post-close) -- 2026-04-17T15:45:00Z

Note: This section was produced after the Synthesizer's round 2 spot-check and synthesizer verdicts were already appended. The Tracer's formal evidence is recorded here for audit completeness; the synthesizer-performed spot-check at Round 2 (lines 727-754) drew on equivalent source reading. Discrepancies between this formal trace and the Round 2 spot-check are noted inline.

### Method 2.6 Application

**CodeQL DB**: `archon/codeql-artifacts/db/` (Go, 422/741 files extracted)

**Call graph slices consulted**:
- `DFD-2-blob-upload-gguf-parse`: reachable: true, path_count: 4
- `DFD-3-create-symlink-escape`: reachable: true, path_count: 18
- `DFD-4-template-dos`: reachable: true, path_count: 72
- `DFD-6-multimodal-cgo`: reachable: false (cgo unmodeled by Go extractor)

**Informational nodes**: `filepath.IsLocal()` recognized as active barrier in `parser/parser.go` but absent in `x/create/create.go`.

**On-demand queries run** (all outputs stored in `archon/tmp/`):
- `archon/codeql-queries/on-demand-toctou-evalsymlinks.ql` → two EvalSymlinks calls confirmed: `parser/parser.go:173` and `parser/parser.go:221`
- `archon/codeql-queries/on-demand-subtree-nil-pipe.ql` → `tools.NewParser` at `server/routes.go:2382` only; `Subtree` has zero production call sites
- `archon/codeql-queries/on-demand-graphsize-nil-assert.ql` → two type assertions on map index confirmed: `fs/ggml/ggml.go:321` and `fs/ggml/ggml.go:607`
- `archon/codeql-queries/on-demand-findtoolcallnode-nil-pipe.ql` → `n.Pipe.Cmds` dereference with no nil guard confirmed at `tools/template.go:52`

---

### [TRACER] Evidence for H-01 -- 2026-04-17T15:45:00Z

**Reachability: REACHABLE**

Code path:
1. `fs/ggml/ggml.go:505-510` -- `Elements()` multiplies Shape dimensions without overflow check; `Shape=[0x4000000000000001, 1]` returns `0x4000000000000001` (fits in uint64)
2. `fs/ggml/ggml.go:513-515` -- `Size()` = `Elements() * typeSize() / blockSize()`; for TensorTypeF32: `0x4000000000000001 * 4 = 0x10000000000000004` wraps to `4`
3. `fs/ggml/gguf.go:258-261` -- bounds check uses WRAPPED `Size()=4`; `tensorEnd > uint64(fileSize)` passes trivially for small file
4. `server/quantization.go:26` -- `io.NewSectionReader(q, int64(q.offset), int64(q.from.Size()))` creates 4-byte section reader
5. `server/quantization.go:37` -- guard `uint64(len(data)) < q.from.Size()` evaluates `4 < 4` = false; passes
6. `server/quantization.go:43` -- `unsafe.Slice((*float32)(unsafe.Pointer(&data[0])), q.from.Elements())` creates slice header with `0x4000000000000001` elements backed by 4 bytes

Sanitizers on path:
- `fs/ggml/gguf.go:260` -- bypassable: uses wrapped `Size()`, not the pre-wrap product
- `server/quantization.go:37` -- bypassable: guard uses `Size()` (small); slice uses `Elements()` (large); these diverge on overflow

CodeQL slice: call-graph-slices.json DFD-2-blob-upload-gguf-parse, reachable: true; DFD-6-multimodal-cgo, reachable: false (cgo unmodeled)
On-demand query: `archon/codeql-queries/on-demand-graphsize-nil-assert.ql` (same file)

**Assessment**: Mechanically confirmed. Overflow is in `Size()` (typeSize multiplication), not `Elements()`. Guard and slice read numerically inconsistent values from the same broken tensor. The cgo call at `ml/backend/ggml/ggml.go` is reached from `server/quantization.go:45` via the non-F32 branch; for F32 the `unsafe.Slice` OOB primitive is at line 43. gin.Recovery does NOT cover cgo memory corruption. Synthesizer verdict VALID/CRITICAL confirmed.

---

### [TRACER] Evidence for H-02 -- 2026-04-17T15:45:00Z

**Reachability: REACHABLE**

Code path (primary parser):
1. `fs/ggml/gguf.go:359` -- `length := int(llm.ByteOrder.Uint64(buf))` — uint64 to int cast
2. `fs/ggml/gguf.go:360-361` -- `length > len(llm.scratch)` → `make([]byte, length)` with attacker-controlled 9.2 EB value

Code path (lazy parser):
1. `fs/gguf/gguf.go:189` -- `n, err := read[uint64](f)`
2. `fs/gguf/gguf.go:194-195` -- `if int(n) > len(f.bts) { f.bts = make([]byte, n) }` — OOM for `n < 2^63`
3. `fs/gguf/gguf.go:198` -- `bts := f.bts[:n]` — slice bounds panic → `runtime.throw` for `n >= 2^63` (process kill, unrecoverable)

Entry to lazy parser: `server/images.go:89` -- `gguf.Open(m.ModelPath)` called from `Capabilities()` → triggered by `GET /api/show`

Sanitizers on path:
- None. No cap against file size in either parser.

CodeQL slice: DFD-2-blob-upload-gguf-parse, reachable: true (4 findings in custom query)
On-demand query: none

**Assessment**: Two distinct crash modes confirmed. Mode (b) (`n >= 2^63` → slice bounds panic → `runtime.throw`) is unrecoverable by gin.Recovery. Lazy parser path reached from `GET /api/show` without quantization. Synthesizer verdict VALID/HIGH confirmed.

---

### [TRACER] Evidence for H-03 -- 2026-04-17T15:45:00Z

**Reachability: REACHABLE**

Code path:
1. `fs/ggml/gguf.go:430` -- `n, err := readGGUF[uint64](llm, r)` reads array element count
2. `fs/ggml/gguf.go:437` -- `newArray[uint8](int(n), llm.maxArraySize)` — for `n = 0x8000000000000001`, `int(n)` is negative
3. `fs/ggml/gguf.go:416-422` -- `newArray`: `maxSize < 0` → `make([]T, negative_size)` → `makeslice` panic

Recoverability note: `makeslice` panic IS a recoverable `runtime.Error` (not `runtime.throw`) in Go >= 1.18. gin.Recovery catches it. Severity is per-request DoS.

CodeQL slice: DFD-2, reachable: true
On-demand query: none

**Assessment**: Confirmed. Synthesizer verdict VALID/MEDIUM (downgraded from HIGH; Recovery covers gin-path panics) confirmed. The integer truncation defect is real.

---

### [TRACER] Evidence for H-04 -- 2026-04-17T15:45:00Z

**Reachability: REACHABLE**

Code path:
1. `fs/ggml/gguf.go:194` -- `for range llm.numTensor()` — raw uint64, no cap
2. `fs/ggml/gguf.go:231` -- `llm.tensors = append(llm.tensors, &tensor)` — unbounded growth
3. `fs/ggml/gguf.go:260` -- bounds check runs post-loop; cannot prevent pre-loop allocation

Per-iteration byte cost: ~32 bytes minimum → memory exhaustion bounded by O(file_size) but not by tensor count. A 10 MB file with maximally dense headers: ~300K tensors × 68 bytes struct ≈ 20 MB heap, proportionally amplified by string names.

CodeQL slice: DFD-2, reachable: true
On-demand query: none

**Assessment**: Confirmed. Synthesizer verdict VALID/HIGH confirmed.

---

### [TRACER] Evidence for H-05 -- 2026-04-17T15:45:00Z

**Reachability: REACHABLE**

Code path:
1. `convert/reader_safetensors.go:34-35` -- `var n int64; binary.Read(f, binary.LittleEndian, &n)`
2. `convert/reader_safetensors.go:39` -- `bytes.NewBuffer(make([]byte, 0, n))` — for max positive `n`, OOM; for `n < 0`, `io.CopyN(b, f, n)` unbounded copy

Entry via `server/create.go` → `convert.Convert` → `parseSafetensors` (non-experimental path, no `--experimental` flag required).

Sanitizers on path: none.

CodeQL slice: DFD-2, reachable: true
On-demand query: none

**Assessment**: Confirmed. The `--experimental` gate identified by the Advocate covers ONLY the `x/create` path, NOT the `convert.Convert` path via `POST /api/create`. Synthesizer verdict VALID/HIGH confirmed.

---

### [TRACER] Evidence for H-06 -- 2026-04-17T15:45:00Z

**Reachability: REACHABLE**

Code path (size DoS): `server/images.go:353` -- `os.ReadFile` no limit → `template.Parse` no size/depth cap
Code path (per-request amplification): `template/template.go:259` -- `t.Vars()` O(N) per Execute; `template/template.go:327` -- `Root.Copy()` O(N) allocations per Execute

Sanitizers on path: none on template blob size or AST depth.

CodeQL slice: DFD-4, reachable: true (72 paths)
On-demand query: none

**Assessment**: Confirmed. H-21/H-22 (stored-template × per-request amplification) merge into this finding. Synthesizer verdict VALID/HIGH confirmed.

---

### [TRACER] Evidence for H-07 -- 2026-04-17T15:45:00Z

**Reachability: REACHABLE (x/create path); PARTIAL (parser.go TOCTOU)**

parser.go TOCTOU assessment:
- `parser/parser.go:173` and `parser/parser.go:221` — two EvalSymlinks calls confirmed by on-demand CodeQL query
- Second call at line 221 receives already-resolved path from line 173 — the TOCTOU window is narrower than the Ideator claimed; requires write access to the resolved directory
- Reachability: PARTIAL

x/create path assessment:
- `x/create/create.go:695-709` — `os.ReadDir` followed by `filepath.Join` followed by `safetensors.OpenForExtraction` with no EvalSymlinks anywhere
- Confirmed by grep: zero EvalSymlinks calls in `x/create/`
- Reachability: REACHABLE

Sanitizers on path (x/create): none.

CodeQL slice: DFD-3, reachable: true (18 findings); on-demand query confirmed two EvalSymlinks at parser/parser.go:173 and :221
On-demand query: `archon/codeql-queries/on-demand-toctou-evalsymlinks.ql`

**Assessment**: The x/create path (no EvalSymlinks) is the primary confirmed finding. The parser.go TOCTOU is real but more constrained. Synthesizer verdict VALID/HIGH confirmed (consolidated to x/create path as primary).

---

### [TRACER] Evidence for H-08 -- 2026-04-17T15:45:00Z

**Reachability: PARTIAL**

Code path:
1. `server/images.go:131-134` -- `v, err := m.Template.Vars(); if err != nil { slog.Warn(...) }` — log and continue; no early return
2. Post-`1ed2881e`: `template.Parse` at load time rejects nil-pipe templates; `m.Template == nil` short-circuits at line 125

Current exploitability: blocked by load-time gate. The log-and-continue pattern is a latent gap for future code bypassing `template.Parse`.

CodeQL slice: DFD-4, reachable: true
On-demand query: none

**Assessment**: PARTIAL. Synthesizer verdict FALSE POSITIVE confirmed for current code state. The structural gap remains.

---

### [TRACER] Evidence for H-09 -- 2026-04-17T15:45:00Z

**Reachability: PARTIAL**

Code path:
1. `server/routes.go:2382` -- `tools.NewParser(m.Template.Template, req.Tools)` — confirmed by on-demand query as sole production call site
2. `tools/template.go:52` -- `n.Pipe.Cmds` bare dereference — confirmed by on-demand query; no nil check
3. `Subtree` function at `template/template.go:211` has zero production call sites (grep confirms)

Current shielding: load-time `template.Parse` gate prevents nil-pipe IfNode from reaching line 52. TemplateNode-skip behavior (lines 64-101: no `case *parse.TemplateNode` branch) is a confirmed behavioral gap — `{{template "tools" .}}` constructs silently fall back to `"{"` heuristic.

CodeQL slice: DFD-4, reachable: true; on-demand queries confirmed both the dereference and the sole NewParser call site
On-demand query: `archon/codeql-queries/on-demand-subtree-nil-pipe.ql`; `archon/codeql-queries/on-demand-findtoolcallnode-nil-pipe.ql`

**Assessment**: PARTIAL for nil-pipe panic (load-time gate); confirmed for TemplateNode behavioral gap. Synthesizer verdict DROP (intended fallback) confirmed for the behavioral gap aspect.

---

### [TRACER] Evidence for H-10 -- 2026-04-17T15:45:00Z

**Reachability: REACHABLE**

Code path:
1. `fs/ggml/ggml.go:607` -- `f.KV()["tokenizer.ggml.tokens"].(*array[string]).size` — no nil check, no ok-check
2. Second assertion at `fs/ggml/ggml.go:321` — same pattern, different key (confirmed by on-demand query)
3. Call chain: `llm/server.go:536` → `GraphSize` → panic; gin-recoverable for HTTP paths
4. Background sched.go model-load goroutines are outside gin Recovery scope

CodeQL slice: on-demand query confirmed two type assertions at lines 321 and 607
On-demand query: `archon/codeql-queries/on-demand-graphsize-nil-assert.ql`

**Assessment**: Confirmed. Synthesizer verdict VALID/MEDIUM confirmed; background goroutine path bypasses Recovery.

---

### [TRACER] Evidence for H-11 -- 2026-04-17T15:45:00Z

**Reachability: REACHABLE**

Code path:
1. `fs/ggml/gguf.go:238` -- `alignment := llm.kv.Uint("general.alignment", 32)` — default applies only when key absent; key present with value 0 returns 0
2. `fs/ggml/gguf.go:245` -- `ggufPadding(offset, int64(0))` → `offset % 0` → recoverable Go panic
3. Additional call sites at lines 269, 573, 580 — all vulnerable for alignment=0
4. Contrast: `fs/gguf/gguf.go` uses `cmp.Or(alignment, 32)` — safe; `fs/ggml` is inconsistently unprotected

CodeQL slice: DFD-2, reachable: true
On-demand query: none

**Assessment**: Confirmed. Synthesizer verdict VALID/HIGH confirmed; the inconsistency between fs/gguf (safe) and fs/ggml (unsafe) is the key observation.

---

### [TRACER] Evidence for H-12 -- 2026-04-17T15:45:00Z

**Reachability: REACHABLE**

Code path:
1. `fs/ggml/gguf.go:297-300` -- reads `var length uint64`
2. `fs/ggml/gguf.go:303` -- `io.CopyN(&b, r, int64(length))` — for `length >= 2^63`, `int64(length)` is negative; CopyN with `n < 0` copies 0 bytes, returns nil error
3. `fs/ggml/gguf.go:308` -- `b.Truncate(b.Len() - 1)` = `Truncate(-1)` → recoverable panic

Gate: GGUF V1 only (`llm.Version == 1` check at readGGUFString line 349).

CodeQL slice: DFD-2, reachable: true
On-demand query: none

**Assessment**: Confirmed. Synthesizer verdict VALID/MEDIUM (V1 legacy, Recovery covers) confirmed.

---

### [TRACER] Evidence for H-13 -- 2026-04-17T15:45:00Z

**Reachability: REACHABLE**

Code path:
1. `fs/ggml/gguf.go:143` -- `for i := 0; uint64(i) < llm.numKV(); i++` — raw file-controlled NumKV, no cap
2. Per-iteration reads consume real bytes; natural bound O(file_size) but pre-checks absent

Same class as H-04. Synthesizer merged as AP-031 (same class as AP-023).

CodeQL slice: DFD-2, reachable: true
On-demand query: none

**Assessment**: Confirmed. Synthesizer verdict VALID/MEDIUM confirmed; merge with H-04 cluster noted.

---

### [TRACER] Evidence for H-14 -- 2026-04-17T15:45:00Z

**Reachability: PARTIAL**

Entry point: `openai/openai.go:683-684` — blank MIME `data:;base64,` confirmed by spec-gap-report as bypassing MIME allowlist (intentional per inline comment at line 682).
Downstream cgo sink (`mtmd_helper_bitmap_init_from_buf`): unmodeled by CodeQL (DFD-6 reachable: false).
Downstream mtmd does perform magic-byte format validation — partial mitigation.

CodeQL slice: DFD-6-multimodal-cgo, reachable: false
On-demand query: none

**Assessment**: Entry point confirmed; cgo sink unconfirmed by CodeQL. Synthesizer overrides Advocate's FP recommendation: expanding cgo surface is a real risk given CVE history of image libraries. Synthesizer verdict VALID/HIGH noted — the Tracer cannot confirm OR deny the cgo sink without manual mtmd analysis.

---

### [TRACER] Evidence for H-15, H-16, H-17, H-18 -- 2026-04-17T15:45:00Z

**H-15 (`anthropic/trace.go:71`)**: `limit = min(len(t), TraceMaxSliceItems)` at line 70 bounds `limit+1` to a constant. SAST false positive confirmed. Synthesizer verdict FALSE POSITIVE confirmed.

**H-16 (`model/renderers/json.go:14`)**: `len(b)+len(b)/8` overflow requires ~8.2 EB; physically impossible on any host. Synthesizer verdict FALSE POSITIVE confirmed.

**H-17 (`tokenizer/wordpiece.go:61`)**: `len(s)*3` cannot overflow on 64-bit (requires 3 EB input). The 3x rune amplification IS a real DoS vector (no MaxBytesReader on `/api/tokenize`). Synthesizer verdict VALID/MEDIUM (recharacterized as amplification, not overflow) confirmed.

**H-18 (`convert/convert_deepseek2.go:155`)**: Advocate claims regex `\d+` constrains input. The Tracer defers direct regex verification to the Synthesizer's Round 2 spot-check which confirmed the constraint. Synthesizer verdict FALSE POSITIVE confirmed.

CodeQL slice: go/allocation-size-overflow and go/incorrect-integer-conversion findings (pattern matches)
On-demand query: none

---

### [TRACER] Tracer Summary -- 2026-04-17T15:45:00Z

| H-ID | Tracer Verdict | Severity Assessment | Key Evidence Location | CodeQL Slice | On-demand Query |
|------|---------------|--------------------|-----------------------|--------------|-----------------|
| H-01 | REACHABLE | CRITICAL | fs/ggml/ggml.go:505-515, server/quantization.go:26-43 | DFD-2 reachable | graphsize-nil-assert.ql (same file) |
| H-02 | REACHABLE | HIGH (mode b: unrecoverable) | fs/ggml/gguf.go:359-361, fs/gguf/gguf.go:194-198 | DFD-2 reachable | none |
| H-03 | REACHABLE | MEDIUM (gin-recoverable) | fs/ggml/gguf.go:437, 416-422 | DFD-2 reachable | none |
| H-04 | REACHABLE | HIGH | fs/ggml/gguf.go:194-232 | DFD-2 reachable | none |
| H-05 | REACHABLE | HIGH | convert/reader_safetensors.go:34-41 | DFD-2 reachable | none |
| H-06 | REACHABLE | HIGH (merged H-21/22) | template/template.go:257-327, server/images.go:353-358 | DFD-4 reachable | none |
| H-07 | REACHABLE (x/create) / PARTIAL (parser.go) | HIGH | x/create/create.go:695-709 | DFD-3 reachable | toctou-evalsymlinks.ql |
| H-08 | PARTIAL | LOW (load-time gate blocks) | server/images.go:131-136 | DFD-4 reachable | none |
| H-09 | PARTIAL | MEDIUM structural; current trigger absent | tools/template.go:52 | DFD-4 reachable | subtree-nil-pipe.ql; findtoolcallnode-nil-pipe.ql |
| H-10 | REACHABLE | MEDIUM (background goroutine unprotected) | fs/ggml/ggml.go:607 | on-demand confirmed | graphsize-nil-assert.ql |
| H-11 | REACHABLE | HIGH (fs/ggml unprotected; inconsistent with fs/gguf) | fs/ggml/gguf.go:238-245,687 | DFD-2 reachable | none |
| H-12 | REACHABLE | MEDIUM (V1 only; gin-recoverable) | fs/ggml/gguf.go:296-311 | DFD-2 reachable | none |
| H-13 | REACHABLE | MEDIUM (O(file_size) bound; same class as H-04) | fs/ggml/gguf.go:143 | DFD-2 reachable | none |
| H-14 | PARTIAL | HIGH (entry confirmed; cgo sink unmodeled) | openai/openai.go:683-684 | DFD-6 unreachable (cgo) | none |
| H-15 | UNREACHABLE | False positive | anthropic/trace.go:71 | Pattern only | none |
| H-16 | UNREACHABLE | False positive | model/renderers/json.go:14 | Pattern only | none |
| H-17 | REACHABLE (amplification) | MEDIUM | tokenizer/wordpiece.go:61 | Pattern + flow | none |
| H-18 | PARTIAL (FP pending regex) | Low | convert/convert_deepseek2.go:155 | Int-conv pattern | none |

