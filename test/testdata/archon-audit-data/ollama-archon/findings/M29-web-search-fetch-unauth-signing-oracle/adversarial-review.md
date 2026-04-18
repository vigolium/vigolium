Adversarial Review: web-search-fetch-unauth-signing-oracle
Reviewer isolation: Cold verification, no Phase 8 context read
Date: 2026-04-17

Step 1 - Restate and Decompose
-------------------------------

Restatement: The gin router registers two POST routes under /api/experimental (web_search and web_fetch) with no per-route authentication. A request to either route flows into webExperimentalProxyHandler, which forwards the request body verbatim to ollama.com, signing the outbound HTTP request with the local user's ed25519 private key via auth.Sign. A network-reachable attacker would therefore be able to issue arbitrary cloud search/fetch calls attributed to the victim's ollama.com identity.

Sub-claims:
  A. Attacker can reach the daemon's experimental routes without local-user credentials.
  B. The request body is forwarded to ollama.com with the attacker's payload intact.
  C. The outbound request is signed with the victim's ~/.ollama/id_ed25519, causing ollama.com to attribute/bill the operation to the victim.

Step 2 - Independent Code Path Trace
------------------------------------

server/routes.go:1707-1708 registers POST /api/experimental/web_search and web_fetch to WebSearchExperimentalHandler and WebFetchExperimentalHandler. No per-route middleware beyond the router-global cors and allowedHostsMiddleware(s.addr).

WebSearchExperimentalHandler (server/routes.go:1958-1964) calls webExperimentalProxyHandler with proxyPath "/api/web_search" and cloudErrWebSearchUnavailable.

webExperimentalProxyHandler (routes.go:1966-1979) reads request body via readRequestBody, rejects empty bodies, and calls proxyCloudRequestWithPath(c, body, proxyPath, ...).

proxyCloudRequestWithPath (server/cloud_proxy.go:179-268):
- checks internalcloud.Status for a global cloud-disabled flag
- constructs outbound URL https://ollama.com:443/api/web_search (or /api/web_fetch)
- copies headers with copyProxyRequestHeaders
- calls cloudProxySignRequest(outReq.Context(), outReq) (line 210) before http.DefaultClient.Do

cloudProxySignRequest -> signCloudProxyRequest (cloud_proxy.go:360-374):
- only signs when req.URL.Hostname() == cloudProxySigningHost (default "ollama.com")
- builds challenge via buildCloudSignatureChallenge -> fmt.Sprintf("%s,%s", req.Method, req.URL.RequestURI())
  * NOTE: signed data is only METHOD and URL.RequestURI with appended ts query param. NOT the body.
- signature, err := auth.Sign(ctx, []byte(challenge))
- sets req.Header["Authorization"] = signature

auth.Sign (auth/auth.go:53-85):
- reads ~/.ollama/id_ed25519
- ssh.ParsePrivateKey, privateKey.Sign(rand.Reader, bts)
- returns "<pubkey-base64>:<signature-base64>"

Discrepancy noted: draft says signing covers "request body+headers+path"; actual signed bytes are METHOD and URL.RequestURI only. Body is NOT signed. This weakens the "signing oracle" framing but does not eliminate the abuse (ollama.com attributes the authenticated request to the key-owner irrespective of body content).

Step 3 - Protection Surface Search
----------------------------------

Layer | Protection Present | Blocks This Attack?
Language | Go, memory safe | n/a
Framework | gin router | no per-route auth registered (routes.go:1707-1708)
Middleware | allowedHostsMiddleware (routes.go:1608-1644) | YES when bind is loopback AND host header is foreign; NO when bind is non-loopback (short-circuits on line 1615-1618 c.Next())
Middleware | CORS (routes.go:1672-1679) | AllowOrigins list covers only local origins + app:// etc. Would block browser drive-by from attacker.com origin but not raw curl from the LAN
Application | internalcloud.Status disabled check | only blocks if user explicitly disabled cloud
Application | request body required | only enforces non-empty; content unfiltered
Application | No CSRF token, no bearer, no confirmation prompt

Critical observation: auth.Sign is called identically by many other handlers (server/auth.go:68, anthropic/anthropic.go:1141, api/client.go:89, app/updater/updater.go:85, x/tools/*). Any daemon route that eventually relays to ollama.com (Pull, Push, Chat cloud models, /v1/chat/completions via cloudPassthroughMiddleware, etc.) invokes the same signing path. The trust model is "any request that reaches the daemon through the host-header gate is the local user."

Documentation search: the daemon's loopback-only binding plus the allowedHostsMiddleware host gate are the documented trust boundary.

Step 4 - Real-Environment Reproduction
--------------------------------------

Environment: macOS, ollama 0.18.3 running on 127.0.0.1:11434. Local key present (~/.ollama/id_ed25519). Account NOT signed in to ollama.com (api/me returns signin_url).

Healthcheck: curl http://127.0.0.1:11434/api/version -> HTTP 200 {"version":"0.18.3"}. OK.

Attempt 1: POST /api/experimental/web_search from loopback with no auth:
  HTTP 401 with response headers Server: Google Frontend, X-Cloud-Trace-Context, Alt-Svc, Via: 1.1 google.
  These headers prove the local daemon accepted the inbound request, invoked signing, and forwarded to ollama.com. ollama.com returned 401 because this device's key is not associated with a signed-in account.

Attempt 2: POST /api/experimental/web_search with Host: attacker.com:
  HTTP 403 from allowedHostsMiddleware. Confirms host gate works when daemon binds to loopback. Remote reachability requires chained dependency on p8-060 (0.0.0.0 bind bypasses gate via short-circuit) or p8-061 (.localhost DNS).

Attempt 3: Could not simulate a signed-in victim without real ollama.com credentials. Billing effect cannot be observed directly.

PoC-Status classification: the signing pipeline executes end-to-end and reaches ollama.com; the billing/history-poisoning impact is conditional on the victim being signed in, which my test environment does not satisfy. Partial executed; full impact theoretical.

Evidence saved: archon/real-env-evidence/web-search-fetch-unauth-signing-oracle/evidence.txt

Step 5 - Prosecution and Defense Briefs
----------------------------------------

Prosecution:
  The POST /api/experimental/web_search and /api/experimental/web_fetch routes have zero per-route auth. Any request that traverses allowedHostsMiddleware successfully triggers cloudProxySignRequest, which invokes auth.Sign over the local ed25519 private key and attaches the signature to an outbound ollama.com request whose body was supplied by the attacker. Real-environment reproduction confirms the signing pipeline executes to completion and the signed request reaches ollama.com (upstream Google Frontend headers visible). Combined with p8-060 (0.0.0.0 bind on LAN/WSL/Docker) the allowedHostsMiddleware short-circuits on line 1615-1618, allowing any network-adjacent attacker to exercise the victim's cloud-API identity. When the victim is signed in, queries are charged to their account and their search history on ollama.com is poisoned with attacker-chosen strings. web_fetch is especially dangerous because it retrieves attacker-chosen URLs through the cloud, turning the victim's account into a mediator for a signed pseudo-SSRF.

Defense:
  The daemon's documented trust model is "localhost equals local user." Every inference, pull, push, and cloud-passthrough route in the daemon operates under the same trust assumption - there is no per-endpoint auth anywhere in the daemon. The web_search and web_fetch routes are not uniquely privileged; the same ~/.ollama/id_ed25519 signing is performed by /api/pull, /api/push, /api/copy, /v1/chat/completions cloud routing, anthropic web search, app/updater, and all x/tools paths. Singling out these two routes as a signing oracle implies they differ from peer routes, but they do not.

  Additionally, the finding's "signing oracle" framing misrepresents the signed data. auth.Sign in cloudProxySignRequest signs only "METHOD,/api/web_search?ts=UNIXTS" - not the body, not arbitrary attacker-chosen bytes. Ollama.com's verifier can only authenticate that a method+path+timestamp tuple was signed; it does not grant attacker-directed signing.

  Exploitation is strictly conditional on two chained prerequisites. Without p8-060 (non-loopback bind) or p8-061 (.localhost drive-by) the attacker cannot reach the daemon at all. Each of those chained findings is a vulnerability on its own; this finding reduces to a defense-in-depth observation against that chained model, not a standalone issue. Furthermore, the billing/history effect is conditional on the victim being signed in to ollama.com - a precondition that neither the daemon nor the finding can guarantee. Real-environment reproduction on a key-present-but-not-signed-in device returned upstream 401 with no side effect.

Step 6 - Severity Challenge
---------------------------

Start at MEDIUM.
Upgrade factors:
  - Remotely triggerable? Only via chained dependency. Not on its own. -> no upgrade
  - Trust boundary crossing? Yes - network to local cryptographic identity to remote account. -> modest
  - No significant preconditions? Fails - requires p8-060 or p8-061 AND victim signed in. -> no upgrade
  - RCE / full auth bypass / mass data exfil? No. -> no CRITICAL
Downgrade factors:
  - Chained dependency on other findings: yes
  - Trust model is uniform across all daemon routes: yes
  - Signing is not attacker-directed (challenge is METHOD+PATH only): yes
  - Billing impact contingent on signed-in account: yes
  - Draft severity (HIGH) overstates a chained, trust-model property

Challenged severity: MEDIUM (downgraded from HIGH). The issue is genuine in the sense the code has no per-route auth, but the impact requires chained preconditions and is not uniquely worse than many peer routes.

Step 7 - Verdict
----------------

CONFIRMED.

The prosecution brief survives: there is demonstrably no per-route auth, the signing pipeline does execute, and the upstream call does reach ollama.com with the victim's signature attached. Real-environment reproduction confirms the signing pipeline. The defense raises valid points about trust-model uniformity and chained preconditions, but those arguments justify a severity downgrade rather than dismissal: the code behavior the finding describes is objectively present and does create a cloud-identity abuse primitive when chained with p8-060 or p8-061.

Severity-Final: MEDIUM (challenged down from HIGH)
PoC-Status: executed (partial - signing pipeline confirmed reaches ollama.com; billing effect requires signed-in victim not present in test env)

Notes / discrepancies flagged:
  - Draft incorrectly states the signature covers "request body+headers+path". Actual signed data is METHOD,URL.RequestURI only (cloud_proxy.go:376-382).
  - The "signing oracle" framing is not accurate; this is an authenticated-proxy-abuse primitive, not a challenge-response oracle.
  - The finding is a property of the daemon's trust model applied to two specific routes, not a unique vulnerability of those routes.
