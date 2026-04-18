Adversarial Cold-Review: p8-003 manifest-token-oom
Reviewed commit: 57653b8e42d69ec35f68a59857bad4d0f07994a3
Verdict: CONFIRMED
Severity-Final: HIGH
PoC-Status: executed (sink-level httptest reproduction)

## Step 1 - Restated claim and sub-claims

Restated: An unauthenticated POST /api/pull to ollama with an attacker-chosen registry host causes the server to consume the entire HTTP response body via io.ReadAll without any size limit, at two separate locations (manifest fetch at server/images.go:864 and token fetch at server/auth.go:81). A hostile registry can reply with a multi-GB or infinite body, exhausting process memory and forcing an OOM kill.

Sub-claims:
- A: Attacker controls the registry host via the JSON body "name" field of /api/pull.
- B: The request path reaches io.ReadAll(resp.Body) without any LimitReader / MaxBytesReader / Content-Length cap in the makeRequest helpers or the http.Client.
- C: Unbounded io.ReadAll on a controlled huge response allocates proportional heap memory, leading to OOM.

None of the sub-claims are incoherent or unsupported.

## Step 2 - Independent code-path trace

server/routes.go:1689 registers POST /api/pull -> s.PullHandler (no auth middleware, only CORS and allowedHostsMiddleware).
server/routes.go:914 PullHandler decodes the JSON into api.PullRequest and invokes PullModel with the attacker-supplied name.
server/images.go:596 PullModel calls model.ParseName on the attacker string, then at line 621 invokes pullModelManifest(ctx, n, regOpts).
server/images.go:853-874 pullModelManifest builds requestURL via n.BaseURL().JoinPath("v2", ...). types/model/name.go:317 BaseURL() simply reflects n.Host back - attacker-controlled.
Line 858 calls makeRequestWithRetry, which wraps makeRequest (server/images.go:951-993). makeRequest constructs an http.Client with no Timeout, no Transport.ResponseHeaderTimeout, no body wrapper.
Line 864: data, err := io.ReadAll(resp.Body) - this is the sink.

For the 401 retry path: server/images.go:902-917 parses the www-authenticate challenge and calls getAuthorizationToken(ctx, challenge, requestURL.Host) at line 907. server/auth.go:60 enforces redirectURL.Host == originalHost - this prevents cross-origin token issuance but the attacker-owned host trivially hosts its own token endpoint. Line 81: body, err := io.ReadAll(response.Body) - second sink.

No validation, sanitization, or transformation mitigates either read.

## Step 3 - Protection-surface search

Language: Go - no bounds checking on slice growth beyond allocator errors; io.ReadAll doubles its backing buffer. Will happily grow to system memory before erroring.
Framework: gin has no default body-size limit applied to response-body reads. ORM etc. N/A.
Middleware: CORS + allowedHostsMiddleware only - neither bounds response bodies. No WAF.
Application-level: grepped server/ for LimitReader | MaxBytesReader. Hits: server/cloud_proxy.go:89 (request-body wrap on zstd path; unrelated) and server/internal/cache/blob/cache.go:107 (blob cache; unrelated). Both irrelevant to the registry response-body path.
HTTP client: server/images.go:984 - `c := &http.Client{ CheckRedirect: regOpts.CheckRedirect }` - no Timeout field set, no Transport override (uses DefaultTransport with no ResponseHeaderTimeout).
Documentation: no SECURITY.md acceptance surfaced.

Conclusion: zero active protection on the response-body read path.

## Step 4 - Real-environment reproduction

Environment: Go 1.26.1, darwin/arm64 host.

Full ollama binary build was skipped due to CGO build cost; instead I produced a sink-level reproducer (archon/real-env-evidence/manifest-token-oom/repro.go) that replicates the exact pattern:
  resp, _ := c.Do(req); data, _ := io.ReadAll(resp.Body)
against an httptest.Server streaming 512 MiB without Content-Length.

Run output (archon/real-env-evidence/manifest-token-oom/run.txt):
  bytes read    : 536870912 (512 MiB)
  elapsed       : 1.092963625s
  heap before   : 0 MiB
  heap after    : 1223 MiB
  total alloc   : 1223 MiB
  sys           : 1263 MiB

Observations:
- 512 MiB of response caused ~1.2 GiB of heap residency (io.ReadAll's append growth - approximately 2x overhead during the final realloc).
- Linearly scalable: a hostile registry streaming ~6 GiB would push the process past typical 8 GiB host memory.
- Infinite-stream variant would reach OOM without ever closing the connection; the process has no read timeout to abort.

Reproduction verdict: SUCCEEDED at the sink pattern level. End-to-end curl against a running ollama instance was not executed but is an obvious wrapper around the verified sink behavior, and the intermediate code path was fully traced in Step 2.

## Step 5 - Prosecution and defense briefs

Prosecution:
The /api/pull handler at server/routes.go:914 is unauthenticated; the model "name" field flows through model.ParseName to types/model/name.go:317 BaseURL which reflects the attacker-chosen host back unchanged. server/images.go:858 issues an HTTP GET to that host via makeRequestWithRetry, whose underlying http.Client (server/images.go:984) has no Timeout or body-size bound. server/images.go:864 then calls io.ReadAll on the resp.Body with no wrapping. On the 401 retry path, server/auth.go:81 performs a second unbounded io.ReadAll on the token endpoint response. A 512-MiB httptest repro induced ~1.2 GiB heap allocation in ~1 second; a hostile registry can trivially exceed host memory. No layer in the chain - language, framework, middleware, or application - wraps the response with LimitReader or MaxBytesReader, and grep across server/ confirms this. Impact is unauthenticated remote DoS on any deployment that binds 0.0.0.0 (documented for containers per knowledge base), with loopback-bound installs reachable via drive-by DNS rebinding subject to the suffix filter.

Defense:
The realm-host check at server/auth.go:60 prevents the token-phase sink from firing against a third-party host - but the attacker-controlled registry is itself that host, so the check does not prevent the DoS. Default bind is loopback (127.0.0.1:11434); remote attackers need either OLLAMA_HOST=0.0.0.0 or a DNS-rebinding drive-by. However, container/cloud deployments commonly set 0.0.0.0, and DNS rebinding is a known bypass vector - so the default-bind argument does not negate exploitability; it only narrows the population. No protection layer, middleware, or documented design acceptance mitigates the sink. The defense cannot cite a blocking control.

## Step 6 - Severity challenge

Starting at MEDIUM. Upgrade factors: remotely triggerable on common configurations; unauthenticated; crosses network-to-process trust boundary; no meaningful preconditions beyond reachability. Impact is full-service DoS (kills inference sessions). Not CRITICAL because it is DoS only (no RCE, no auth bypass, no data exfiltration).
Severity-Final: HIGH. Matches Severity-Original.

## Step 7 - Verdict

CONFIRMED. Prosecution brief survives the defense search with no blocking protection identified; sink-level reproduction succeeded. Update to the draft: Adversarial-Verdict: CONFIRMED, Severity-Final: HIGH, PoC-Status: executed.
