# Cross-Model Seeds: Group C

## CROSS-01: Host Bypass Chain → Unauthenticated Signing Key Proxy

Source-A: PH-04 from backward-reasoner (`.localhost` suffix bypass)
Source-B: PH-10 from contradiction-reasoner (non-loopback bind disables all validation)
Connection: Both PH-04 and PH-10 are alternative ways to bypass `allowedHostsMiddleware` at the same function (`routes.go:1608`). Once either bypass is achieved, the attacker reaches the same unauthenticated endpoints (web_search, web_fetch from PH-05). PH-04 applies when the server is loopback-bound; PH-10 applies when bound to `0.0.0.0`. Together they cover all bind configurations.
Combined hypothesis: On any Ollama deployment — whether loopback (`.localhost` suffix bypass) or LAN-exposed (non-loopback short-circuit) — an attacker can reach `/api/experimental/web_search` and `/api/experimental/web_fetch` without authentication, using the victim's signing key to make ollama.com API calls at the victim's expense. The two vectors are mutually complementary and together eliminate any safe configuration.
Test direction for causal-verifier: Verify that (a) with `OLLAMA_HOST=127.0.0.1`, a request with `Host: evil.localhost` is forwarded; (b) with `OLLAMA_HOST=0.0.0.0`, any Host is accepted; (c) in both cases POST `/api/experimental/web_search` succeeds with any body.

---

## CROSS-02: Unbounded Body + Double Buffering → Amplified OOM

Source-A: PH-02 from backward-reasoner (unbounded `readRequestBody` on `/v1/*`)
Source-B: PH-14 from contradiction-reasoner (`cloudPassthroughMiddleware` buffers then `ChatMiddleware` re-buffers)
Connection: Both reference the exact same code path: `cloudPassthroughMiddleware` → `readRequestBody` → `io.ReadAll` at `cloud_proxy.go:294`. PH-02 identifies the primitive; PH-14 explains that the body is then allocated a SECOND time in the `bytes.Buffer` inside `ChatMiddleware`/`EmbeddingsMiddleware`. The combined effect is that a single large POST causes at minimum 2× the body size in heap allocations before any request processing occurs.
Combined hypothesis: A POST to `/v1/chat/completions` with a 1GB non-zstd body causes 2GB of heap allocation (one in `readRequestBody`'s byte slice, one in the `bytes.Buffer` that `ChatMiddleware` encodes the converted request into). This 2× amplification factor makes OOM DoS feasible with a smaller body than PH-02 alone suggests.
Test direction for causal-verifier: Trace the allocation path from `readRequestBody` through `ChatMiddleware.json.NewEncoder(&b).Encode(chatReq)` to confirm two independent allocations of body-scale data. Check if any of gin's or the JSON decoder's intermediate buffers add further amplification.

---

## CROSS-03: client2 Middleware Skip + SSRF via `/api/pull`

Source-A: PH-03 from backward-reasoner (client2 skips `allowedHostsMiddleware` for `/api/pull`)
Source-B: PH-16 from contradiction-reasoner (`req.Insecure` enables HTTP SSRF on any host)
Connection: Both target `/api/pull`. PH-03 shows the host-validation gate is entirely absent when client2 is active. PH-16 shows that even WITH host validation, the pull host itself is not allowlisted. Combined: client2 + `insecure:true` enables an attacker on any origin (no DNS rebinding needed) to issue HTTP requests to any host the server can reach, with the body contents of responses surfaced in error messages.
Combined hypothesis: With `OLLAMA_EXPERIMENT=client2` enabled: a browser from `http://evil.com` can POST `http://ollama-server:11434/api/pull {"model":"169.254.169.254/v2/latest","insecure":true}` — the gin middleware chain is bypassed, the pull issues `GET http://169.254.169.254/v2/v2/latest/manifests/latest`, and the response (IMDS metadata) is returned in the error message to the browser.
Test direction for causal-verifier: Confirm that `registry/server.go:serveHTTP` case `/api/pull` calls `s.handlePull` which calls into `PullModel`; confirm that `PullModel` → `pullModelManifest` builds URL with `http://` scheme when `Insecure=true` and that the manifest-fetch error message propagates back to the HTTP response.

---

## CROSS-04: `.localhost` Suffix Bypass + Public Key Oracle → Phishing Pivot

Source-A: PH-04 from backward-reasoner (`.localhost` suffix accepted in Host header)
Source-B: PH-06 from backward-reasoner (public key leaked via `/api/me`)
Connection: Both target the same trust boundary (allowedHostsMiddleware → WhoamiHandler). PH-04 shows how to bypass the host check; PH-06 shows what the attacker gains once they bypass it. The public key recovery via `/api/me` is a prerequisite for the phishing attack described in PH-06 (forged signin_url).
Combined hypothesis: From a web page hosted at `http://victim.localhost` (or via any of the CORS-wildcard origins like `app://*`, `vscode-webview://*`), an attacker can POST to `/api/me` with `Host: victim.localhost`, receive the victim's ollama.com public key and hostname, and construct a forged `https://ollama.com/connect?name=<victim>&key=<attacker-key>` URL that the Ollama CLI will print without host-pinning validation. This requires the victim to click the link, but the prerequisites are trivial.
Test direction for causal-verifier: Verify that (a) CORS `AllowOrigins` includes wildcard patterns that an attacker page could satisfy; (b) `Host: victim.localhost` satisfies `allowedHost`; (c) the `signin_url` in the response contains the base64 public key; (d) `cmd/cmd.go` prints the `signin_url` without domain validation.

---

## CROSS-05: Anthropic Web Search Double-Proxy + Unbounded Body Buffering

Source-A: PH-01 (unbounded body in webExperimentalProxyHandler) + PH-13 (Anthropic web search bypasses normal cloud abort)
Source-B: PH-14 (double-buffering in cloudPassthroughMiddleware → ChatMiddleware)
Connection: The Anthropic web search path (PH-13) takes the `c.Next()` branch from `cloudPassthroughMiddleware`, which means the body was ALREADY fully buffered by `readRequestBody` in that middleware. `AnthropicMessagesMiddleware` then re-reads and re-encodes the body (another allocation). `ChatHandler` then proxies the re-encoded Ollama request to ollama.com, which may trigger a follow-up web_search orchestration loop in `WebSearchAnthropicWriter` — each loop iteration issues further outbound requests. A sufficiently complex web_search tool invocation creates a cascading allocation + outbound request pattern.
Combined hypothesis: A single POST to `/v1/messages` with a web_search tool and a large context can trigger: (1) body buffering in cloudPassthroughMiddleware, (2) re-encoding in AnthropicMessagesMiddleware, (3) proxying to ollama.com, (4) multiple follow-up web_search → ChatHandler → cloud proxy iterations. Each iteration allocates. The loop is bounded by ollama.com response content but driven by attacker-controlled tool invocations.
Test direction for causal-verifier: Review `middleware/anthropic.go` `WebSearchAnthropicWriter` loop logic to determine whether the number of web_search iterations is bounded; confirm whether each loop re-reads and re-encodes the request body or reuses a cached copy.
