Adversarial review: readrequestbody-unbounded-cloud-proxy
Commit: 57653b8e42d69ec35f68a59857bad4d0f07994a3

Step 1 — Restated claim
The cloud-passthrough entry `readRequestBody` reads the entire HTTP body with
`io.ReadAll` and no size cap. Any plain (non-zstd) POST to endpoints that
mount `cloudPassthroughMiddleware` or `webExperimentalProxyHandler` will have
its body buffered into memory in full, enabling a single-request memory
exhaustion DoS. The zstd branch correctly caps at 20 MiB; the non-zstd branch
does not.

Sub-claims:
A. Attacker controls the HTTP body size on POST to cloud-passthrough routes.
B. The body reaches `io.ReadAll` without any interposing MaxBytesReader / LimitReader.
C. The resulting unbounded allocation allows OOM/GC-pressure DoS.

All sub-claims are internally coherent.

Step 2 — Independent code trace
Entry: POST /v1/chat/completions (and sibling OpenAI-compat + experimental routes).
  -> server/routes.go:1720 mounts cloudPassthroughMiddleware in the handler chain.
  -> server/cloud_proxy.go:73 cloudPassthroughMiddleware.
     - Line 75-78: non-POST short-circuit (not an attack gate, just a filter).
     - Line 81-91: zstd branch — wraps body with MaxBytesReader(20 MiB). Only
       reached if Content-Encoding: zstd.
     - Line 97: readRequestBody(c.Request) is called unconditionally for POST.
  -> server/cloud_proxy.go:289 readRequestBody.
     - Line 294: body, err := io.ReadAll(r.Body) — no wrapping.
Direct second entry: server/routes.go:1707-1708,1966-1978 — `/api/experimental/web_search`
and `/api/experimental/web_fetch` call readRequestBody directly.

No intermediate sanitization, validation, or size cap on this path. The
function restores r.Body as a NopCloser (line 299), confirming the whole body
is materialized in memory before downstream handlers run.

Step 3 — Protection surface search
- Language: Go slice growth allowed up to available heap. No protection.
- Framework: gin.Default at routes.go:1674 — no BodyLimit. Gin has no default
  body cap.
- http.Server at routes.go:1811 has no MaxHeaderBytes, no ReadTimeout, no
  handler-level body cap.
- allowedHostsMiddleware at routes.go:1608-1644: ONLY applies when bound to
  loopback. If bound to non-loopback (0.0.0.0, LAN IP) it short-circuits at
  line 1615-1618 with c.Next() and does not filter hosts. So on loopback,
  remote reach requires either rebinding or a Host-header-accepted origin;
  on non-loopback there is no network-level gate.
- CORS allows custom origins via envconfig.AllowedOrigins(); browsers will
  preflight cross-origin JSON POSTs, which provides some drive-by protection
  but does not block server-side attackers or same-origin scripts.
- Docs: No SECURITY.md entry declaring unbounded body as accepted risk.

No layer blocks the claimed attack on the non-zstd path. The 20 MiB cap in
the zstd branch is a local mitigation for one encoding, not a global cap.

Step 4 — Real-environment reproduction
Environment: native `go test` against server package at HEAD commit.
Healthcheck: existing TestCloudPassthroughMiddleware_ZstdBodyTooLarge test
confirms the test harness exercises cloudPassthroughMiddleware normally.

Reproduction: wrote TestReadRequestBody_Uncapped_512MiB using a streaming
fakeReader that emits 512 MiB of 'A' without pre-allocating. POST to
/v1/chat/completions with cloudPassthroughMiddleware mounted.

Result: PASS. 512 MiB body fully read in 577 ms. Handler received all 512 MiB.
No cap triggered. Status 200.

Evidence: /Users/bytedance/Desktop/demo/ollama/archon/real-env-evidence/readrequestbody-unbounded-cloud-proxy/reproduction.txt
Test source: /Users/bytedance/Desktop/demo/ollama/archon/real-env-evidence/readrequestbody-unbounded-cloud-proxy/unbounded_test.go

The test stops at 512 MiB to avoid OOM-ing the reviewer's machine; the linear
scaling (577 ms / 512 MiB ~= 1.1 ms/MiB with constant-time Reader calls) and
the absence of any cap in the code path implies multi-GB requests behave
identically until the OS kills the process.

Step 5 — Briefs
Prosecution: See the enumerated code locations above. A non-zstd POST on any
of seven enumerated routes reaches io.ReadAll with no size bound. The real
http.Server has no overriding cap. allowedHostsMiddleware does not apply to
non-loopback binds. Reproduction succeeded against the actual code.

Defense: The default bind is loopback; remote reach requires OLLAMA_HOST=
0.0.0.0 or a DNS-rebinding chain. The attack is DoS-only, no data leak.
Reproduction uses httptest in-process and does not demonstrate that a real
TCP client can stream 4 GB before the OS or network intervenes. Defense-in-
depth hardening, not a break.

Assessment: the defense adds mitigations but does not block the path.
Reproduction demonstrated 512 MiB of actual memory consumption through the
real middleware chain — not a theoretical concern.

Step 6 — Severity
Starting at MEDIUM. Remote reach requires non-default bind (documented and
common in Docker/WSL2/LAN). No auth bypass, no RCE, no data exfil — purely
availability. Single-request DoS against a specific configuration profile.
- CRITICAL: requires default-internet-facing; Ollama default is loopback. No.
- HIGH: would need unconditional remote trigger OR meaningful data impact.
  Neither holds.
- MEDIUM: reasonable given availability-only impact behind a config
  precondition. The draft's original HIGH rested on chaining with separate
  findings; taken alone this is MEDIUM.

Step 7 — Verdict
CONFIRMED at MEDIUM. PoC-Status: executed.
Adversarial-Verdict written back to draft.
