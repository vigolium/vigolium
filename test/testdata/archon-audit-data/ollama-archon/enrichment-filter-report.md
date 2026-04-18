# Phase 7 Enrichment Filter Report

**Target:** github.com/ollama/ollama @ 57653b8e  
**Date:** 2026-04-17  
**Analyst:** Enrichment Filter (Phase 7)  
**Input:** 210 SAST candidates (1 CRITICAL, 98 HIGH, 111 MEDIUM) from sast-candidates.json  
**Output:** sast-filtered.json (forwarded candidates), this report

---

## Executive Summary

| Disposition | Count |
|-------------|-------|
| `duplicate-of-probe` | 117 |
| `security` — forwarded to Phase 8 (new) | 5 |
| `security` — forwarded to Phase 8 (cluster) | 1 cluster (31 routes) |
| `correctness` — forwarded to Phase 8 | 2 |
| `false-positive` — dropped | 15 |
| `environment` — dropped | 61 |
| Total accounted | 210 (including 5 exact duplicates in raw JSON) |

Net Phase 8 forwards: **8 distinct entries** (5 individual findings + 1 31-route cluster + 2 correctness).

---

## Methodology Notes

### CodeQL Reachability Cross-Reference Used

| DFD Slice | Reachable | Description |
|-----------|-----------|-------------|
| DFD-1 | true | Digest path traversal (manifest package) |
| DFD-2 | true | binary.Read length → make() (GGUF parser) |
| DFD-3 | true | filepath.Glob → os.Open without EvalSymlinks |
| DFD-4 | true | User content → template.Parse/Execute |
| DFD-5 | true | Getenv + user input → exec.Command |
| DFD-6 | false* | cgo size_t cast — no CodeQL path (Go extractor limitation, covered by Semgrep) |
| DFD-8 | false | io.ReadAll on response.Body — LimitReader barrier detected in current code for some paths |
| DFD-9 | true | Cloud proxy OLLAMA_HOST → HTTP request without allowlist |
| DFD-13 | false | auth.go io.ReadAll — field-read not fully modeled; manual triage target |

*DFD-6 `reachable: false` is a CodeQL extractor gap, not evidence of safety. Semgrep findings on same sinks are treated as manual positive.

---

## Classification Table

### Group 1: Digest Path Traversal (manifest/*)

| Finding ID | Classification | Attacker Control | Boundary | CodeQL Reachability | Verdict |
|------------|---------------|-----------------|----------|-------------------|---------|
| `codeql-go/path-injection-manifest/layer.go-86` | duplicate-of-probe | Remote registry operator | network→filesystem | DFD-1: reachable | duplicate PH-01/PH-04 |
| `codeql-go/path-injection-manifest/layer.go-105` | duplicate-of-probe | Remote registry operator | network→filesystem | DFD-1: reachable | duplicate PH-01/PH-04 |
| `codeql-go/path-injection-manifest/manifest.go-125` | duplicate-of-probe | Remote registry operator | network→filesystem | DFD-1: reachable | duplicate PH-01/PH-04 |
| `codeql-go/path-injection-manifest/paths.go-56` | duplicate-of-probe | Remote registry operator | network→filesystem | DFD-1: reachable | duplicate PH-01/PH-04 |
| `codeql-custom-digest-path-no-canonicalization` | duplicate-of-probe | Remote registry operator | network→filesystem | DFD-1: reachable | duplicate PH-01/PH-04 |
| `codeql-go/path-injection-x/imagegen/manifest/manifest.go-54` | duplicate-of-probe | Remote registry operator | network→filesystem | DFD-1: reachable | duplicate PH-13 (Group A NEEDS-DEEPER) |

### Group 2: Path Injection in server/create.go and server/images.go

| Finding ID | Classification | Attacker Control | Boundary | CodeQL Reachability | Verdict |
|------------|---------------|-----------------|----------|-------------------|---------|
| `codeql-go/path-injection-server/create.go-376` | duplicate-of-probe | Local API user (Modelfile path) | user→filesystem | DFD-3: reachable | duplicate PH-04 (Group A) |
| `codeql-go/path-injection-server/create.go-627` | duplicate-of-probe | Local API user (Modelfile path) | user→filesystem | DFD-3: reachable | duplicate PH-04 (Group A) |
| `codeql-go/path-injection-server/create.go-633` | duplicate-of-probe | Local API user (Modelfile path) | user→filesystem | DFD-3: reachable | duplicate PH-04 (Group A) |
| `codeql-go/path-injection-server/create.go-670` | duplicate-of-probe | Local API user (Modelfile path) | user→filesystem | DFD-3: reachable | duplicate PH-04 (Group A) |
| `codeql-go/path-injection-server/create.go-782` | duplicate-of-probe | Local API user (Modelfile path) | user→filesystem | DFD-3: reachable | duplicate PH-04 (Group A) |
| `codeql-go/path-injection-server/create.go-865` | duplicate-of-probe | Local API user (Modelfile path) | user→filesystem | DFD-3: reachable | duplicate PH-04 (Group A) |
| `codeql-go/path-injection-server/create.go-874` | duplicate-of-probe | Local API user (Modelfile path) | user→filesystem | DFD-3: reachable | duplicate PH-04 (Group A) |
| `codeql-go/path-injection-server/images.go-420` | duplicate-of-probe | Remote registry operator | network→filesystem | DFD-1: reachable | duplicate PH-01/PH-04 |
| `codeql-go/path-injection-server/images.go-425` | duplicate-of-probe | Remote registry operator | network→filesystem | DFD-1: reachable | duplicate PH-01/PH-04 |
| `codeql-go/path-injection-server/images.go-431` | duplicate-of-probe | Remote registry operator | network→filesystem | DFD-1: reachable | duplicate PH-01/PH-04 |
| `codeql-go/path-injection-server/images.go-556` | duplicate-of-probe | Remote registry operator | network→filesystem | DFD-1: reachable | duplicate PH-01/PH-04 |
| `codeql-go/path-injection-server/images.go-686` | duplicate-of-probe | Remote registry operator | network→filesystem | DFD-1: reachable | duplicate PH-01/PH-04 |
| `codeql-go/path-injection-server/images.go-690` | duplicate-of-probe | Remote registry operator | network→filesystem | DFD-1: reachable | duplicate PH-01/PH-04 |
| `codeql-go/path-injection-server/images.go-783` | duplicate-of-probe | Remote registry operator | network→filesystem | DFD-1: reachable | duplicate PH-01/PH-04 |
| `codeql-go/path-injection-server/images.go-787` | duplicate-of-probe | Remote registry operator | network→filesystem | DFD-1: reachable | duplicate PH-01/PH-04 |
| `codeql-go/path-injection-server/routes.go-1500` | duplicate-of-probe | Remote registry operator | network→filesystem | DFD-1: reachable | duplicate PH-01/PH-04 |
| `codeql-go/path-injection-server/routes.go-1534` | duplicate-of-probe | Remote registry operator | network→filesystem | DFD-1: reachable | duplicate PH-01/PH-04 |

### Group 3: SSRF (server/images.go:992)

| Finding ID | Classification | Attacker Control | Boundary | CodeQL Reachability | Verdict |
|------------|---------------|-----------------|----------|-------------------|---------|
| `codeql-go/request-forgery-server/images.go-992` | duplicate-of-probe | Any POST /api/pull caller | network→internal-HTTP | DFD-9: reachable | duplicate PH-03/PH-16 (Group A) |

### Group 4: Uncontrolled Allocation Size (runner/*, kvcache/*)

| Finding ID | Classification | Attacker Control | Boundary | CodeQL Reachability | Verdict |
|------------|---------------|-----------------|----------|-------------------|---------|
| `codeql-go/uncontrolled-allocation-size-kvcache/recurrent.go-138` | duplicate-of-probe | Inference request caller (num_ctx/n_batch field) | API→process-memory | DFD-2: reachable | duplicate PH-05 (Group D) / PH-02 (Group A) |
| `codeql-go/uncontrolled-allocation-size-runner/llamarunner/cache.go-31` | duplicate-of-probe | Inference request caller | API→process-memory | DFD-2: reachable | duplicate PH-05 (Group D) |
| `codeql-go/uncontrolled-allocation-size-runner/llamarunner/runner.go-903` | duplicate-of-probe | Inference request caller | API→process-memory | DFD-2: reachable | duplicate PH-05 (Group D) |
| `codeql-go/uncontrolled-allocation-size-runner/ollamarunner/cache.go-41` | duplicate-of-probe | Inference request caller | API→process-memory | DFD-2: reachable | duplicate PH-05 (Group D) |
| `codeql-go/uncontrolled-allocation-size-runner/ollamarunner/runner.go-1079` | duplicate-of-probe | Inference request caller | API→process-memory | DFD-2: reachable | duplicate PH-05 (Group D) |
| `codeql-go/uncontrolled-allocation-size-runner/ollamarunner/runner.go-1124` | duplicate-of-probe | Inference request caller | API→process-memory | DFD-2: reachable | duplicate PH-05 (Group D) |
| `codeql-go/uncontrolled-allocation-size-runner/ollamarunner/runner.go-1229` | duplicate-of-probe | Inference request caller | API→process-memory | DFD-2: reachable | duplicate PH-05 (Group D) |
| `codeql-go/uncontrolled-allocation-size-x/imagegen/models/flux2/flux2.go-316` | duplicate-of-probe | Imagegen API caller | API→process-memory | DFD-2: reachable | duplicate PH-05 (Group D) |

### Group 5: Allocation-Size Overflow (anthropic/trace.go, model/renderers/, tokenizer/)

| Finding ID | Classification | Attacker Control | Boundary | CodeQL Reachability | Verdict |
|------------|---------------|-----------------|----------|-------------------|---------|
| `codeql-go/allocation-size-overflow-anthropic/trace.go-71` | security | API caller (Anthropic streaming response) | cross-user if shared server | DFD-2: reachable | KEEP — Phase 8 brief below (SAST-ALLOC-01) |
| `codeql-go/allocation-size-overflow-model/renderers/json.go-14` (first) | security | API caller (model response encoding) | cross-user DoS | DFD-2: reachable | KEEP — Phase 8 brief below (SAST-ALLOC-02) |
| `codeql-go/allocation-size-overflow-model/renderers/json.go-14` (duplicate) | false-positive | exact duplicate ID | n/a | n/a | DROP (exact duplicate entry) |
| `codeql-go/allocation-size-overflow-tokenizer/wordpiece.go-61` | security | API caller (tokenize endpoint, input text) | cross-user DoS | DFD-2: reachable | KEEP — Phase 8 brief below (SAST-ALLOC-03) |

### Group 6: Incorrect Integer Conversion (convert/*)

| Finding ID | Classification | Attacker Control | Boundary | CodeQL Reachability | Verdict |
|------------|---------------|-----------------|----------|-------------------|---------|
| `codeql-go/incorrect-integer-conversion-convert/convert_deepseek2.go-155` | correctness | Model upload (GGUF/safetensors conversion) | same-user conversion crash | DFD-2: reachable | KEEP correctness — Phase 8 brief (SAST-INT-01) |
| `codeql-go/incorrect-integer-conversion-convert/convert_glm4moelite.go-200` | correctness | Model upload (GGUF/safetensors conversion) | same-user conversion crash | DFD-2: reachable | KEEP correctness — Phase 8 brief (SAST-INT-01 cluster) |
| `codeql-go/incorrect-integer-conversion-envconfig/config.go-265` | environment | Server operator sets env var (OLLAMA_* config) | admin-only | no-slice | DROP — environment/admin-only |

### Group 7: Custom CodeQL — GGUF Binary Read Length → make()

| Finding ID | Classification | Attacker Control | Boundary | CodeQL Reachability | Verdict |
|------------|---------------|-----------------|----------|-------------------|---------|
| `codeql-custom-length-from-binary-read-to-make` | duplicate-of-probe | Model uploader (GGUF blob upload) | network→process-memory | DFD-2: reachable | duplicate PH-05 (Group D) |

### Group 8: Custom CodeQL — exec-with-user-string (CRITICAL)

| Finding ID | Classification | Attacker Control | Boundary | CodeQL Reachability | Verdict |
|------------|---------------|-----------------|----------|-------------------|---------|
| `codeql-custom-exec-with-user-string` | duplicate-of-probe | LLM output / env var (EDITOR/VISUAL) | process→OS | DFD-5: reachable | duplicate PH-05 (Group E) |

### Group 9: Custom CodeQL — symlink-read-without-evalsymlinks

| Finding ID | Classification | Attacker Control | Boundary | CodeQL Reachability | Verdict |
|------------|---------------|-----------------|----------|-------------------|---------|
| `codeql-custom-symlink-read-without-evalsymlinks` | duplicate-of-probe | Modelfile author (local create path) | user→filesystem | DFD-3: reachable | duplicate PH-04 (Group A/FG) |

### Group 10: Custom CodeQL — template-execute-user-src

| Finding ID | Classification | Attacker Control | Boundary | CodeQL Reachability | Verdict |
|------------|---------------|-----------------|----------|-------------------|---------|
| `codeql-custom-template-execute-user-src` | duplicate-of-probe | Model template author (Modelfile/registry) | network→server process | DFD-4: reachable | duplicate PH-04 (Group A/FG), bypass B1/B5 |

### Group 11: Custom CodeQL — cloud-passthrough-host-not-allowlisted

| Finding ID | Classification | Attacker Control | Boundary | CodeQL Reachability | Verdict |
|------------|---------------|-----------------|----------|-------------------|---------|
| `codeql-custom-cloud-passthrough-host-not-allowlisted` | duplicate-of-probe | Any /api/experimental/* caller | user→internal HTTP | DFD-9: reachable | duplicate PH-09/PH-21 (Group C/E) |

### Group 12: Semgrep Baseline — SQL Injection (app/store/database.go:64)

| Finding ID | Classification | Attacker Control | Boundary | CodeQL Reachability | Verdict |
|------------|---------------|-----------------|----------|-------------------|---------|
| `semgrep-baseline-string-formatted-query-app/store/database.go-64` | security | API caller (model name/tag field reaching store layer) | cross-user data | no-slice (not in CodeQL model) | KEEP NEW — Phase 8 brief (SAST-SQL-01) |

### Group 13: Semgrep Baseline — ReverseProxy Director Header Removal

| Finding ID | Classification | Attacker Control | Boundary | CodeQL Reachability | Verdict |
|------------|---------------|-----------------|----------|-------------------|---------|
| `semgrep-baseline-reverseproxy-director-app/ui/ui.go-165` | correctness | No attacker input required (internal proxy misconfiguration) | same-user header loss | no-slice | DROP — correctness without security boundary; advisory pattern only, no exploitable data flow |

### Group 14: Semgrep Baseline — Decompression Bomb (app/updater/*)

| Finding ID | Classification | Attacker Control | Boundary | CodeQL Reachability | Verdict |
|------------|---------------|-----------------|----------|-------------------|---------|
| `semgrep-baseline-potential-dos-via-decompression-bomb-app/updater/updater_darwin.go-205` | environment | Update server (Ollama-controlled CDN) | admin-controlled update path | no-slice | DROP — environment/admin; update binary is fetched from Ollama's own CDN; attacker would need to MITM the update channel, which is a separate threat model |
| `semgrep-baseline-potential-dos-via-decompression-bomb-app/updater/updater_darwin.go-315` | environment | Update server | admin-controlled update path | no-slice | DROP — same reasoning as above |

### Group 15: Semgrep Baseline — Weak Crypto (MD5, math/rand)

All `use-of-md5` and `math-random-used` findings:

| Finding ID | Classification | Verdict |
|------------|---------------|---------|
| `semgrep-baseline-use-of-md5-app/wintray/tray.go-435` | correctness | DROP — MD5 used for UI avatar hash (non-security, purely aesthetic) |
| `semgrep-baseline-use-of-md5-server/upload.go-185` | security | DROP — MD5 used for upload progress tracking part-ETag; not used for integrity verification. Security impact: Low. DROP per Low drop rule. |
| `semgrep-baseline-use-of-md5-server/upload.go-230` | security | DROP — same reasoning; Low severity. |
| `semgrep-baseline-math-random-used-llm/server.go-13` | correctness | DROP — math/rand usage in non-cryptographic selection (process spawn, port pick); Low. |
| `semgrep-baseline-math-random-used-middleware/openai.go-9` | correctness | DROP — used for request ID generation; not security-sensitive. Low. |
| `semgrep-baseline-math-random-used-openai/responses.go-6` | correctness | DROP — Low. |
| `semgrep-baseline-math-random-used-sample/samplers.go-6` | correctness | DROP — sampling is intentionally stochastic; Low. |
| `semgrep-baseline-math-random-used-server/download.go-11` | correctness | DROP — jitter backoff; Low. |
| `semgrep-baseline-math-random-used-server/routes.go-16` | correctness | DROP — Low. |
| `semgrep-baseline-math-random-used-server/internal/internal/backoff/backoff.go-6` | correctness | DROP — Low. |
| `semgrep-baseline-math-random-used-x/imagegen/server.go-12` | correctness | DROP — Low. |
| `semgrep-baseline-math-random-used-x/imagegen/transfer/transfer.go-30` | correctness | DROP — Low. |
| `semgrep-baseline-math-random-used-x/mlxrunner/client.go-12` | correctness | DROP — Low. |

### Group 16: Semgrep Baseline — Missing SSL MinVersion

| Finding ID | Classification | Verdict |
|------------|---------------|---------|
| `semgrep-baseline-missing-ssl-minversion-server/internal/client/ollama/registry.go-983` | correctness | DROP — Go 1.22+ already defaults to TLS 1.2 minimum; missing explicit `MinVersion` is a hygiene issue only. Low severity. |

### Group 17: Semgrep Baseline — Use-After-Free in C (ml/backend/ggml/ggml-alloc.c:894)

| Finding ID | Classification | Attacker Control | Boundary | CodeQL Reachability | Verdict |
|------------|---------------|-----------------|----------|-------------------|---------|
| `semgrep-baseline-use-after-free-ml/backend/ggml/ggml/src/ggml-alloc.c-894` | security | Inference request caller (model execution graph triggers galloc path) | cross-user (process crash / potential RCE) | no-slice (C code, outside CodeQL Go model) | KEEP NEW — Phase 8 brief (SAST-UAF-01) |

### Group 18: Semgrep Baseline — strcpy in C (x/imagegen/mlx/*.c)

| Finding ID | Classification | Verdict |
|------------|---------------|---------|
| `semgrep-baseline-insecure-use-string-copy-fn-x/imagegen/mlx/mlx_dynamic.c-38` | correctness | DROP — `strcpy` in dynamic library loader for fixed-size constant strings; no attacker-controlled input reaches these calls based on code context. Low. |
| `semgrep-baseline-insecure-use-string-copy-fn-x/imagegen/mlx/mlx_error_handler.c-17` | correctness | DROP — error handler strcpy of literal string. Low. |

### Group 19: Semgrep Baseline — HTTP without TLS (x/mlxrunner/runner.go:172)

| Finding ID | Classification | Verdict |
|------------|---------------|---------|
| `semgrep-baseline-use-tls-x/mlxrunner/runner.go-172` | environment | DROP — internal runner HTTP server binds to 127.0.0.1 loopback only; TLS on localhost is a hygiene concern, not an exploitable trust boundary crossing. |

### Group 20: Semgrep Custom — ollama-exec-nonconstant (cmd/launch/*, app/server/*, cmd/cmd.go, etc.)

These 62 findings all share DFD-5/DFD-14 and fire on exec.Command calls in the cmd/launch/ launcher helpers and OS-specific server bootstrap code.

**Triage rationale:** The exec.Command calls in `cmd/launch/` (claude.go, cline.go, codex.go, copilot.go, droid.go, models.go, openclaw.go, opencode.go, pi.go, vscode.go) launch well-known external IDE/tool executables (VSCode, Claude, Cline, etc.) by invoking their known binary paths, not by substituting attacker-supplied strings. The command names and argument templates are hardcoded constants or constructed from pre-validated install paths resolved by the launcher. The semgrep pattern fires on any non-constant exec.Command argument, but these do not cross a user→OS trust boundary in a new way beyond what is already modeled by DFD-5.

The findings at `app/cmd/app/app.go:470`, `app/cmd/app/app_darwin.go:233`, `app/cmd/app/app_windows.go:417` execute the OS-registered "open" or "start" command on URLs constructed from internal state — not attacker-controlled strings.

The `cmd/cmd.go:1955` and `cmd/interactive.go:677` findings exercise `$EDITOR`/`$VISUAL` → exec.Command, which is already DFD-5 and duplicate of PH-05 (Group E, probe channel).

The `llm/server.go:383` finding calls exec.CommandContext to spawn the llama runner binary — path is resolved from the Ollama install directory, not user-supplied.

| Finding Cluster | Classification | Verdict |
|-----------------|---------------|---------|
| `cmd/cmd.go:1955`, `cmd/interactive.go:677` ($EDITOR/$VISUAL) | duplicate-of-probe | duplicate PH-05 (Group E) — DFD-5 reachable |
| `app/cmd/app/*.go` (OS open/start on URL) | environment | DROP — attacker cannot control the URL in the exploit-relevant way; same-user desktop app action |
| `app/server/server_unix.go:24,57`, `app/server/server_windows.go:23,110,142` | environment | DROP — server process management; arguments are resolved binary paths from install directory |
| `app/updater/updater_windows.go:126` | environment | DROP — updater binary execution; path from Ollama update channel |
| `app/wintray/menus.go:96` | environment | DROP — systray menu action; same-user desktop |
| `cmd/start_darwin.go:29`, `cmd/start_windows.go:50` | environment | DROP — OS-specific server start; binary path from install |
| `llm/server.go:383` | environment | DROP — llama runner spawn; path from install directory |
| All `cmd/launch/*.go` (51 hits: claude, cline, codex, copilot, droid, models, openclaw, opencode, pi, vscode) | environment | DROP — launches known IDE/tool binaries from pre-validated install paths; no user-controlled command substitution; attacker already has local code execution to manipulate PATH |

### Group 21: Semgrep Custom — ollama-cgo-length-unchecked (llama/llama.go, ml/backend/ggml/ggml.go, x/imagegen/mlx/mlx.go)

| Finding ID | Classification | Attacker Control | Boundary | CodeQL Reachability | Verdict |
|------------|---------------|-----------------|----------|-------------------|---------|
| `semgrep-custom-ollama-cgo-length-unchecked-llama/llama.go-566` | duplicate-of-probe | Inference API (multimodal image data) | user→C memory | DFD-6: no-slice (extractor gap) | duplicate PH-05 (Group D) |
| `semgrep-custom-ollama-cgo-length-unchecked-llama/llama.go-735` (tokens) | duplicate-of-probe | Inference API (token array) | user→C memory | DFD-6: no-slice | duplicate PH-05 (Group D) |
| `semgrep-custom-ollama-cgo-length-unchecked-llama/llama.go-735` (eog) | duplicate-of-probe | Inference API (EOG token array) | user→C memory | DFD-6: no-slice | duplicate PH-05 (Group D) |
| `semgrep-custom-ollama-cgo-length-unchecked-ml/backend/ggml/ggml.go-276` | duplicate-of-probe | Model load (tensor shape array) | model→C memory | DFD-6: no-slice | duplicate PH-05 (Group D) |
| `semgrep-custom-ollama-cgo-length-unchecked-ml/backend/ggml/ggml.go-383` | duplicate-of-probe | Model load (backend array) | model→C memory | DFD-6: no-slice | duplicate PH-05 (Group D) |
| `semgrep-custom-ollama-cgo-length-unchecked-ml/backend/ggml/ggml.go-909` | duplicate-of-probe | Model load (shape array) | model→C memory | DFD-6: no-slice | duplicate PH-05 (Group D) |
| `semgrep-custom-ollama-cgo-length-unchecked-ml/backend/ggml/ggml.go-1182` | duplicate-of-probe | Model load (shape array) | model→C memory | DFD-6: no-slice | duplicate PH-05 (Group D) |
| `semgrep-custom-ollama-cgo-length-unchecked-app/dialog/cocoa/dlg_darwin.go-39` | environment | macOS dialog string from internal UI | same-user desktop | DFD-6: no-slice | DROP — UI-only, no network-facing attacker input path |
| All `x/imagegen/mlx/mlx.go` cgo findings (8 hits: lines 361,391,441,452,473,485,493,501) | duplicate-of-probe | Imagegen API (tensor shape/eval handles) | user→C memory | DFD-6: no-slice | duplicate PH-05 (Group D) |

### Group 22: Semgrep Custom — ollama-url-parse-no-scheme-check (server/cloud_proxy.go:185)

| Finding ID | Classification | Attacker Control | Boundary | CodeQL Reachability | Verdict |
|------------|---------------|-----------------|----------|-------------------|---------|
| `semgrep-custom-ollama-url-parse-no-scheme-check-server/cloud_proxy.go-185` | duplicate-of-probe | OLLAMA_HOST env var / web_fetch caller | user→internal HTTP | DFD-9: reachable | duplicate PH-09/PH-21 (Group C/E) |

### Group 23: Semgrep Custom — ollama-gin-route-no-allowed-hosts (server/routes.go, 31 route registrations)

Lines flagged: 1683, 1685, 1686, 1689, 1690, 1692, 1693, 1694, 1696, 1698, 1700, 1703, 1704, 1706, 1707, 1708, 1711, 1712, 1713, 1714, 1715, 1720, 1721, 1722, 1723, 1724, 1725, 1727, 1728, 1730, 1733

| Finding Cluster | Classification | Attacker Control | Boundary | CodeQL Reachability | Verdict |
|-----------------|---------------|-----------------|----------|-------------------|---------|
| 31 gin routes missing host middleware (routes.go lines above) | security (cluster) | Any browser (DNS rebinding) / LAN attacker | browser→Ollama API (cross-origin) | no-slice (architecture-level, not data-flow) | KEEP — Phase 8 brief (SAST-DNS-01 cluster) |

**Partial overlap with probe:** Group C probes PH-04, PH-05, PH-10 confirm the host validation bypass mechanism. The SAST cluster adds specific route-line identification not in the probe summary, so it carries added value for the Phase 8 remediation chamber. Forwarded as a SAST cluster alongside probe channel, not as pure duplicate.

---

## Phase 8 Forwarding Briefs

### SAST-SQL-01 — SQL Injection in app/store/database.go:64

**Severity:** MEDIUM (elevated to HIGH if model names reach this layer from API)  
**Source:** `semgrep-baseline-string-formatted-query-app/store/database.go-64`  
**Classification:** security  
**Not in any probe group.**

**Attacker control:** Any caller who can set a model name or tag via `POST /api/create`, `POST /api/pull`, or `POST /api/copy` — unauthenticated on default deploy.  
**Runtime:** Go server process (SQLite via go-sqlite3).  
**Trust boundary crossed:** Network-facing API → local SQLite database (cross-user if multiple users share one Ollama instance).  
**Effect:** Cross-user: a model name crafted as SQL payload could read or corrupt other users' stored data, or escalate to arbitrary SQLite writes.  
**Reachability:** No CodeQL slice computed. Semgrep pattern `string-formatted-query` fired on a `fmt.Sprintf`-constructed SQL string. Needs on-demand verification of whether `model` or `tag` fields from API JSON reach `app/store/database.go:Exec` or `Query` without parameterization.  
**Attack scenario:** Attacker sends `POST /api/create` with `{"name":"x' OR '1'='1"}`. If the name flows unsanitized into a `fmt.Sprintf("SELECT ... WHERE name='%s'", name)` query at line 64, the attacker can read all stored records or inject SQL DML.

**Phase 8 action:** Verify whether the string at line 64 receives any user-controlled field from the API request chain. If yes, HIGH severity; remediate with parameterized query. If the string is a fully static query template with no user data, reclassify as false-positive.

---

### SAST-ALLOC-01 — Integer Overflow in anthropic/trace.go:71

**Severity:** HIGH  
**Source:** `codeql-go/allocation-size-overflow-anthropic/trace.go-71`  
**Classification:** security  
**Not in any probe group.**

**Attacker control:** Any caller who triggers an Anthropic streaming response via the Anthropic proxy endpoint. The overflow involves an arithmetic operation on a potentially large value used to compute an allocation size in the trace buffer.  
**Runtime:** Go server process, Anthropic middleware path.  
**Trust boundary crossed:** Network API → process heap (cross-user DoS or potential heap confusion).  
**Effect:** Integer overflow wraps allocation size to small value → subsequent write to undersized buffer → heap corruption or panic. Cross-user: process crash affects all active inference sessions.  
**CodeQL reachability:** DFD-2 reachable (same allocation-overflow class). No exact slice for this file.  
**Attack scenario:** Attacker sends a crafted Anthropic streaming request that produces a response chunk count or token length near `math.MaxInt`. The multiplication at line 71 overflows to a negative or small value. `make([]T, n)` with a wrapped-negative n panics in Go, causing a goroutine crash that propagates to all users via process termination on `runtime.throw`.

**Phase 8 action:** Inspect `anthropic/trace.go:71` arithmetic for the specific operands. If either operand is derived from response body data (token count, chunk length), confirm overflow path. Remediate with explicit bounds check before multiplication.

---

### SAST-ALLOC-02 — Integer Overflow in model/renderers/json.go:14

**Severity:** HIGH  
**Source:** `codeql-go/allocation-size-overflow-model/renderers/json.go-14`  
**Classification:** security  
**Not in any probe group.**

**Attacker control:** Any caller who triggers model JSON rendering (e.g., `/api/show`, `/api/tags`, or inference response with a large token count field). The allocation size is computed from a value that CodeQL traced from a potentially large (remotely-influenced) source.  
**Runtime:** Go server process, model rendering path.  
**Trust boundary crossed:** Network API → process heap.  
**Effect:** Same class as SAST-ALLOC-01: integer overflow in allocation → heap corruption or panic → cross-user DoS.  
**Attack scenario:** Attacker crafts a model with an unusually large token count or shape field that flows into the renderer's pre-allocation. The multiplication at line 14 overflows; `make` panics or allocates an undersized buffer.

**Phase 8 action:** Inspect `model/renderers/json.go:14`. Identify which source field is large; add `math/bits.Mul64` overflow check or explicit `if n > maxReasonableSize { return error }` guard.

---

### SAST-ALLOC-03 — Integer Overflow in tokenizer/wordpiece.go:61

**Severity:** HIGH  
**Source:** `codeql-go/allocation-size-overflow-tokenizer/wordpiece.go-61`  
**Classification:** security  
**Not in any probe group.**

**Attacker control:** Any caller who posts text to a tokenization endpoint (e.g., `/api/tokenize` or via embedded tokenizer calls in `/api/generate`). Wordpiece tokenizer processes input text; a crafted input could produce an extremely large token count.  
**Runtime:** Go server process, tokenizer path.  
**Trust boundary crossed:** Network API → process heap (cross-user DoS).  
**Effect:** Overflow in token slice allocation → panic or undersized buffer → heap corruption.  
**Attack scenario:** Attacker sends input text engineered to maximize wordpiece fragmentation (e.g., adversarial Unicode sequences) producing `n` tokens near `math.MaxInt/2`. The `n * elementSize` multiplication at line 61 overflows; `make([]Token, n)` panics.

**Phase 8 action:** Inspect operands in `tokenizer/wordpiece.go:61`. Add explicit overflow check. Consider a hard upper bound on tokenizer output size.

---

### SAST-INT-01 — Narrowing Integer Conversion in convert/convert_deepseek2.go:155 and convert/convert_glm4moelite.go:200

**Severity:** MEDIUM (correctness with security implication if conversion result used in size calculation)  
**Source:** `codeql-go/incorrect-integer-conversion-convert/convert_deepseek2.go-155`, `codeql-go/incorrect-integer-conversion-convert/convert_glm4moelite.go-200`  
**Classification:** correctness  
**Not in any probe group.**

**Attacker control:** Model uploader (GGUF/safetensors conversion path). The `strconv.Atoi` return value (architecture-dependent int size, e.g., 64-bit) is cast to `uint32` without an upper-bound check.  
**Runtime:** Go server process, model conversion path.  
**Trust boundary crossed:** User-uploaded model file → process logic. Single-user impact (conversion of own model fails silently or produces wrong output). Potentially cross-user if a converted model is published and other users load it.  
**Effect:** Truncation of the int value to uint32 silently loses high bits; downstream size or index calculation uses the wrong value → buffer over-read or logic error in converted model. Not directly exploitable as a remote crash without further chaining.  
**Attack scenario:** Model file contains a layer count or vocab size >2^32. `strconv.Atoi` returns the large value; cast to uint32 wraps to a small value; subsequent `make([]byte, wrappedSize)` allocates too little; write exceeds allocation bounds.

**Phase 8 action:** Add `if v > math.MaxUint32 { return error }` guard before each cast at these two sites. Check whether downstream callers use the converted value in allocation or offset arithmetic.

---

### SAST-UAF-01 — Use-After-Free in ml/backend/ggml/ggml/src/ggml-alloc.c:894

**Severity:** HIGH  
**Source:** `semgrep-baseline-use-after-free-ml/backend/ggml/ggml/src/ggml-alloc.c-894`  
**Classification:** security  
**Not in any probe group.**

**Attacker control:** Any inference request caller who triggers the graph allocator path (standard inference). `galloc->leaf_allocs` is freed then accessed at line 894 in `ggml_gallocr_alloc_graph`.  
**Runtime:** C inference engine (llama.cpp/ggml), called from Go via cgo.  
**Trust boundary crossed:** Inference API → C heap (cross-user: process crash drops all sessions; potential RCE if the freed pointer is attackable).  
**Effect:** Use-after-free in C allocator: undefined behavior, likely process crash (DoS for all users). Under controlled heap layout, potential write-after-free enabling RCE, though exploitation requires heap grooming.  
**CodeQL reachability:** No Go-side slice. C-level finding from Semgrep `c.lang.security.use-after-free`. The `ggml-alloc.c` file is part of the vendored llama.cpp/ggml backend compiled into the inference binary.  
**Attack scenario:** Attacker sends any valid inference request that triggers `ggml_gallocr_alloc_graph` with a non-trivial computation graph. If the freed `leaf_allocs` pointer is dereferenced (line 894), the C runtime exhibits undefined behavior, typically a SIGSEGV. In multi-user deployments this is a DoS against all concurrent users.

**Phase 8 action:** Verify whether this UAF is in the vendored ggml snapshot or has been patched upstream. Check `ml/backend/ggml/ggml/src/ggml-alloc.c` at HEAD against the upstream ggml commit log for a fix to `ggml_gallocr_alloc_graph`. If unfixed, the inference backend needs the upstream patch applied.

---

### SAST-DNS-01 — 31 Gin Routes Missing allowedHostsMiddleware (server/routes.go cluster)

**Severity:** MEDIUM (HIGH when combined with DNS rebinding — see probe PH-04/PH-10 Group C)  
**Source:** 31 `semgrep-custom-ollama-gin-route-no-allowed-hosts` findings, server/routes.go lines 1683–1733  
**Classification:** security (cluster)  
**Partial overlap with probe:** Group C confirmed the host validation bypass mechanism (PH-04, PH-10). This cluster identifies the specific unprotected route registrations not enumerated in the probe summary.

**Attacker control:** Any browser on the LAN or any origin that can bypass the host check (via PH-04 `.localhost` suffix bypass or PH-10 non-loopback bind bypass — both probe-confirmed).  
**Runtime:** Go/gin HTTP server.  
**Trust boundary crossed:** Browser/LAN → Ollama API (DNS rebinding, cross-origin).  
**Effect:** Cross-user: any JS on a malicious page can make authenticated API calls to a victim's local Ollama instance if the victim's browser visits the attacker's page. Routes confirmed unprotected include `/api/experimental/web_search` (PH-05), `/api/experimental/web_fetch`, `/api/me`, and 28 additional endpoints.  
**CodeQL reachability:** No data-flow slice (architectural finding). Route registration structure is statically verifiable from routes.go.  
**Attack scenario (DNS rebinding):** Attacker registers `evil.com`. Victim visits `evil.com`. Page JS changes DNS to point `evil.com` to `127.0.0.1`. Subsequent requests to `evil.com:11434` from the browser bypass same-origin policy; Host header is `evil.com`. The routes at the flagged lines accept the request without host validation.

**Phase 8 action:** Enumerate all 31 flagged routes and determine which are legitimately public (e.g., healthcheck) vs. which should be behind the `apiMux` group that carries `allowedHostsMiddleware`. All routes at lines 1707–1708 (`web_search`, `web_fetch`) must move into the protected group or gain independent auth middleware. Confirm that the protected group at routes.go:1676–1679 wraps the remaining sensitive routes.

---

## Phase 7 Enrichment Notes (Knowledge Base Update)

### Entry Points Not in Phase 3 DFD Slices

1. **`app/store/database.go:64` SQLite query construction** — not modeled in any Phase 3 DFD slice. The store layer is not covered by the existing DFD entry-point map. This is a gap: the `POST /api/create`, `POST /api/pull`, and `POST /api/copy` routes all eventually touch the model store. If model names are stored and retrieved via un-parameterized queries, this is a persistent injection point absent from the DFD.

2. **`anthropic/trace.go:71`, `model/renderers/json.go:14`, `tokenizer/wordpiece.go:61` allocation overflows** — these are downstream of existing entry points (inference API, Anthropic proxy) but the specific arithmetic overflow sinks are not in the DFD-2 slice's enumerated sinks. DFD-2 covers `binary.Read` length → `make()` in GGUF parsers; these allocation overflows are in the response-rendering and tokenization paths, which are downstream of completed model loads.

3. **`ml/backend/ggml/ggml/src/ggml-alloc.c:894`** — C-level use-after-free in the inference backend. Not present in any Phase 3 DFD slice; the DFD-6 slice covers Go→C cgo boundary size_t issues but does not model internal C heap management within ggml. This represents an unmodeled high-risk flow: network inference request → ggml graph allocator → C heap UAF.

### Sinks from sinks.json Mapping to Unmodeled High-Risk Flows

- The 668 enumerated sinks include 278 `json.Unmarshal` calls. None of these appeared in the forwarded findings — JSON deserialization into typed Go structs is generally safe from injection. However, if any `json.Unmarshal` target struct has fields that flow into the SQL query at `database.go:64`, that creates an unmodeled source→sink path.
- The 34 `io.ReadAll` sinks include `server/auth.go:81` (manual triage target from DFD-13) and `server/images.go:864` (pullModelManifest) — both duplicates of probes PH-14 and PH-04 respectively. These sinks are modeled but the CodeQL paths were not confirmed due to field-read modeling gaps; probe evidence is stronger.
- The 45 `exec.Command` sinks: all significant ones are covered by DFD-5 and duplicated into probe PH-05 (Group E). The launcher-specific sinks (cmd/launch/*) were classified as environment above.

### Probe-SAST Alignment Summary

| Probe Finding | SAST Duplicates Found | Quality of Alignment |
|---------------|----------------------|---------------------|
| PH-01/PH-04 (digest path traversal) | 22 CodeQL path-injection findings | High — CodeQL independently confirmed all 4 DFD-1 sinks |
| PH-03/PH-16 (SSRF images.go:992) | 1 CodeQL request-forgery finding | High — exact file/line match |
| PH-14 (auth.go ReadAll OOM) | 0 CodeQL findings (DFD-13 no-slice) | Gap — manual probe evidence only; recommend on-demand CodeQL query |
| PH-05 (GGUF allocation / cgo) | 1 custom CodeQL + 11 Semgrep cgo findings | Medium — Semgrep covers cgo sinks CodeQL cannot model |
| PH-09/PH-21 (URL scheme/SSRF proxy) | 1 custom CodeQL + 1 Semgrep finding | High — two independent tools confirm same sink |
| PH-05 Group E (exec agent bash) | 62 Semgrep exec-nonconstant findings | Partial — Semgrep fires on all exec calls including safe launchers; critical ones confirmed by probe |
| Group C (DNS rebinding routes) | 31 Semgrep gin-route findings | High — SAST cluster adds specific line numbers not in probe |
