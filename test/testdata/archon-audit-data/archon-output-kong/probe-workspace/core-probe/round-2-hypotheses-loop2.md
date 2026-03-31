# Round 2 Hypotheses — core-probe

## PH-01: OAuth2 parameter source confusion via merge order

- **Reasoning-Model**: TRIZ
- **Target**: `kong/plugins/oauth2/access.lua:209-217` — `retrieve_parameters()`
- **Attacker starting position**: unauthenticated
- **Attack input / strategy**: Send `POST /oauth2/token?grant_type=refresh_token&client_id=publicA` with body `grant_type=client_credentials&client_id=confidentialB&client_secret=...` (or the reverse), relying on `kong.table.merge(uri_args, body_args)` to pick body values over query values. Repeat with conflicting `redirect_uri`, `scope`, or `authenticated_userid` fields to steer the later checks in `issue_token`.
- **Tension / Game**: **Convenience vs strictness** — allowing OAuth2 params in both query and body for compatibility vs enforcing a single canonical source.
- **What was sacrificed / Information accumulated**: Canonical parameter source; body parameters silently override query parameters. This allows parameter smuggling across layers that inspect only one location (e.g., WAF or proxy checking query but not body).
- **Security consequence**: Potential bypass of upstream parameter validation or policy enforcement; ambiguous request interpretation may lead to unexpected grant type or client_id selection during token issuance.
- **Severity estimate**: MEDIUM
- **Read needed**: `kong/plugins/oauth2/access.lua:209-217`
- **Deepening direction**: Verify how upstream proxies/WAFs or logging treat query vs body for `/oauth2/token`; check if any validation assumes query-only or body-only values.

---

## PH-02: OAuth2 token issuance errors act as client/token oracle

- **Reasoning-Model**: Game-Theory
- **Target**: `kong/plugins/oauth2/access.lua:561-816` — `issue_token()`
- **Attacker starting position**: unauthenticated
- **Attack input / strategy**: Iterate `POST /oauth2/token` with a fixed `grant_type=authorization_code` but varying `client_id` values and bogus `code` values. Observe differences between `invalid_client` (no such client) vs `invalid_request` (client exists but code mismatch) and `invalid_grant` (PKCE verifier mismatch). Repeat for `refresh_token` with guessed tokens to distinguish valid vs invalid refresh tokens.
- **Tension / Game**: **Usability vs confidentiality** — explicit OAuth2 error messaging for developer clarity vs minimizing information leakage.
- **What was sacrificed / Information accumulated**: The error taxonomy reveals which client IDs exist and whether a code/refresh token is structurally valid for a client, enabling incremental enumeration with repeated probes.
- **Security consequence**: Client ID and token validity enumeration that can seed targeted phishing, credential stuffing, or refresh-token guessing strategies.
- **Severity estimate**: MEDIUM
- **Read needed**: `kong/plugins/oauth2/access.lua:561-816`
- **Deepening direction**: Confirm response body/status patterns for each branch (invalid_client vs invalid_request vs invalid_grant) and whether rate limits differ per error.

---

## PH-03: JWT key-claim existence oracle via error differentiation

- **Reasoning-Model**: Game-Theory
- **Target**: `kong/plugins/jwt/handler.lua:170-241` — `do_authentication()`
- **Attacker starting position**: unauthenticated
- **Attack input / strategy**: Send crafted JWTs with varying `conf.key_claim_name` values (e.g., `iss` or `kid`) and an invalid signature. If the claim maps to an existing credential, the response shifts from `No credentials found` to `Invalid signature` or `Invalid algorithm`. Iterate to enumerate valid keys.
- **Tension / Game**: **Debuggability vs privacy** — detailed unauthorized messages to aid clients vs minimizing signal to attackers.
- **What was sacrificed / Information accumulated**: Distinct error messages reveal which key IDs or issuers are registered, enabling adaptive probing across many requests.
- **Security consequence**: Credential enumeration (issuer/key id discovery) that can be leveraged to target specific consumers or focus brute-force/signing attacks.
- **Severity estimate**: MEDIUM
- **Read needed**: `kong/plugins/jwt/handler.lua:170-241`
- **Deepening direction**: Check if error message surfaces to clients verbatim or is normalized; verify if per-IP or per-credential rate limits exist.

---

## PH-04: Cluster RPC handshake CPU drain via cert validation on repeated failures

- **Reasoning-Model**: Game-Theory
- **Target**: `kong/clustering/rpc/manager.lua:507-535` — `handle_websocket()`
- **Attacker starting position**: network-adjacent (can reach CP RPC port)
- **Attack input / strategy**: Open many WebSocket handshakes with `Sec-WebSocket-Protocol: kong.meta.v1` and present invalid or self-signed client certs. Each attempt triggers `validate_client_cert` before the connection is closed; repeat to consume CPU in the cert validation path.
- **Tension / Game**: **Security vs availability** — strict mTLS validation for authenticity vs computational cost per connection.
- **What was sacrificed / Information accumulated**: No explicit pre-validation rate limit or cheap reject before cert parsing; attacker can amortize cost across repeated connections.
- **Security consequence**: CPU exhaustion or reduced availability of the cluster RPC service, possibly degrading CP/DP sync.
- **Severity estimate**: MEDIUM
- **Read needed**: `kong/clustering/rpc/manager.lua:507-535`
- **Deepening direction**: Evaluate whether Nginx-level handshake limits, rate limits, or connection caps mitigate repeated invalid certs.

---

## PH-05: Router flavor transition cache mismatch during reload

- **Reasoning-Model**: TRIZ
- **Target**: `kong/router/init.lua:40-64` — `new()`
- **Attacker starting position**: unauthenticated
- **Attack input / strategy**: During a config reload that changes `router_flavor` (e.g., `traditional` → `expressions`), send bursts of requests crafted to hit cached route entries while `old_router` is still referenced by the new router constructor, attempting to use stale route selection results for protected paths.
- **Tension / Game**: **Compatibility/uptime vs correctness** — reusing `old_router` for smoother transitions vs fully rebuilding routing state.
- **What was sacrificed / Information accumulated**: Potential for stale or mismatched cache keys across flavors during reload, allowing a short window where routing and plugin chain selection may not match updated configuration.
- **Security consequence**: Route/plugin mismatch could lead to bypass or misapplication of auth plugins during reload windows.
- **Severity estimate**: MEDIUM
- **Read needed**: `kong/router/init.lua:40-64`
- **Deepening direction**: Inspect router flavor constructors for cache reuse semantics and whether old/new cache keys differ; confirm reload flow and time window behavior.

---

## Coverage Check

| Entry Point | TRIZ tension found? | Game Theory mechanism found? |
|------------|:-:|:-:|
| `kong/runloop/handler.lua:1211-1225` — router exec | NO — out of scope for loop2 targets | NO — no repeated-interaction mechanism analyzed here |
| `kong/router/traditional.lua:1755-1788` — traditional exec | NO — not targeted in loop2 | NO — not targeted in loop2 |
| `kong/router/atc.lua:443-507` — expressions exec | NO — not targeted in loop2 | NO — not targeted in loop2 |
| `kong/router/utils.lua:57-64` — strip_uri_args | NO — not targeted in loop2 | NO — not targeted in loop2 |
| `kong/runloop/handler.lua:1357-1365` — WebSocket upgrade | NO — not targeted in loop2 | NO — not targeted in loop2 |
| `kong/clustering/control_plane.lua:191-236` — CP websocket | NO — not targeted in loop2 | NO — not targeted in loop2 |
| `kong/clustering/data_plane.lua:200-257` — DP communicate | NO — not targeted in loop2 | NO — not targeted in loop2 |
| `kong/clustering/rpc/manager.lua:507-562` — RPC websocket | PH-04 | PH-04 |
| `kong/runloop/plugin_servers/rpc/mp_rpc.lua:172-218` — MsgPack RPC | NO — not targeted in loop2 | NO — not targeted in loop2 |
| `kong/runloop/plugin_servers/rpc/pb_rpc.lua:268-328` — ProtoBuf RPC | NO — not targeted in loop2 | NO — not targeted in loop2 |
| `kong/plugins/jwt/handler.lua:154-250` — JWT auth | NO — TRIZ not used here | PH-03 |
| `kong/plugins/oauth2/access.lua:209-221` — retrieve_parameters | PH-01 | NO — no repeated-interaction mechanism needed |
| `kong/plugins/oauth2/access.lua:533-812` — issue_token | PH-01 | PH-02 |
| `kong/resty/dns/client.lua:742-883` — DNS query | NO — not targeted in loop2 | NO — not targeted in loop2 |
| `kong/templates/nginx_kong.lua:97-519` — HTTP/2 template | NO — not targeted in loop2 | NO — not targeted in loop2 |

| Trust Chain Gap | TRIZ hypothesis generated? |
|----------------|:-:|
| Router normalization consistency vs HTTP/2 entry | NO — loop2 focus on OAuth2/JWT/cluster/router init only |
| AuthZ decision influenced by external plugin RPC | NO — loop2 focus excludes external RPC | 
| External plugin RPC framing size limits | NO — loop2 focus excludes external RPC |
| CP/DP sync legacy paths | NO — loop2 focus excludes CP/DP sync | 
| DNS resolver safety depends on version | NO — loop2 focus excludes DNS | 
| HTTP/2 core limit enforcement | NO — loop2 focus excludes HTTP/2 | 

| Interactive Mechanism | Game Theory hypothesis generated? |
|----------------------|:-:|
| OAuth2 issue_token error responses | PH-02 / YES — response differentiation enables enumeration |
| JWT auth error responses | PH-03 / YES — response differentiation enables key discovery |
| Cluster RPC handshake validation | PH-04 / YES — repeated invalid handshakes consume resources |
| Router flavor selection/init | NO — not inherently interactive; config-driven |
