# Round 3 Hypotheses — core-probe

## PH-301: HTTP/2 normalization mismatch yields route/auth drift (NEEDS-DEEPER)

- **Reasoning-Model**: Causal
- **Causal Test**: Intervention
- **Origin**: Cross-Model CROSS-01
- **Target**: `kong/router/utils.lua:57-64` — `strip_uri_args → normalize(req_uri, true)`
- **Attacker starting position**: unauthenticated
- **Causal argument**: If Lua-side normalization is bypassed (or diverges from HTTP/2 `:path` canonicalization), routing decisions may follow a different path than upstream canonicalization. The protection (Lua normalization) is only causally necessary if it is the sole source of canonicalization before route match; if HTTP/2 layer already rewrites `:path`, bypassing Lua normalization may not change route selection. This makes the protection potentially non‑causal depending on h2c vs ALPN handling.
- **Real risk**: Route misclassification could apply the wrong auth plugin set (or no auth) relative to the effective upstream path.
- **Attack input**: HTTP/2 request with encoded `%2f`/`%2e` path segments crafted to normalize differently at Lua routing vs upstream resolution.
- **Security consequence**: Auth bypass via route mismatch; unauthorized access to protected upstreams.
- **Severity estimate**: HIGH
- **Read needed**: anatomy sufficient
- **Deepening direction**: Compare Nginx/OpenResty `:path` normalization behavior for h2c vs ALPN against `normalize(req_uri, true)` and confirm whether routing uses pre- or post-normalized URI.

---

## PH-302: External plugin RPC can mutate auth context post-validation (NEEDS-DEEPER)

- **Reasoning-Model**: Causal
- **Causal Test**: Confounder
- **Origin**: Cross-Model CROSS-02
- **Target**: `kong/runloop/plugin_servers/rpc/mp_rpc.lua:172-218` — `call()` (MsgPack RPC)
- **Attacker starting position**: internal service (compromised external plugin server)
- **Causal argument**: Safety appears to assume trusted external plugin servers; the code’s protection is confounded by environment trust. If the plugin server is compromised or untrusted, it may invoke PDK methods that mutate headers or consumer context after JWT/OAuth2 decisions. The apparent safety is external (deployment trust), not enforced by RPC layer.
- **Real risk**: Post-auth mutation of consumer or headers leading to auth bypass or privilege escalation.
- **Attack input**: RPC call sequence invoking PDK methods that set `authenticated_consumer` or override auth headers after JWT/OAuth2 run.
- **Security consequence**: Forged identity or bypass of auth enforcement.
- **Severity estimate**: CRITICAL
- **Read needed**: anatomy sufficient
- **Deepening direction**: Enumerate PDK methods exposed to external plugin servers and confirm whether they can mutate auth/consumer context in the same request phase after auth plugins.

---

## PH-303: Oversized RPC frame causes worker DoS (NEEDS-DEEPER)

- **Reasoning-Model**: Causal
- **Causal Test**: Counterfactual
- **Origin**: Cross-Model CROSS-03
- **Target**: `kong/runloop/plugin_servers/rpc/pb_rpc.lua:268-328` — `call()` (ProtoBuf RPC)
- **Attacker starting position**: internal service (compromised external plugin server)
- **Causal argument**: The protection would be size limits on length-prefixed frames; if such limits only trigger on adversarial oversized frames, normal traffic never exercises them. If no limits exist, then the “safety” is a dormant assumption. The risk is only apparent under adversarial inputs that normal traffic never generates.
- **Real risk**: Memory exhaustion or event-loop blocking due to oversized frames.
- **Attack input**: Length-prefixed frame advertising extremely large payload, causing allocation/receive pressure.
- **Security consequence**: Worker process DoS, degraded availability.
- **Severity estimate**: HIGH
- **Read needed**: anatomy sufficient
- **Deepening direction**: Verify socket receive behavior and any explicit caps or OpenResty/lua_socket constraints for plugin RPC payload sizes.

---

## PH-304: CP/DP legacy sync fallback weakens validation (NEEDS-DEEPER)

- **Reasoning-Model**: Causal
- **Causal Test**: Intervention
- **Origin**: Cross-Model CROSS-04
- **Target**: `kong/clustering/control_plane.lua:191-439` — `handle_cp_websocket`
- **Attacker starting position**: internal service (rogue DP or MITM within cluster)
- **Causal argument**: If protocol negotiation allows fallback to v1 when v2 capabilities are omitted, the stronger v2 validation is not causally necessary. Bypassing v2 validation should not alter whether a malicious DP can deliver/receive config, implying a deeper weakness in v1 validation.
- **Real risk**: Config poisoning or config exfiltration via weaker legacy validation.
- **Attack input**: CP/DP handshake omitting capabilities to force v1, followed by crafted `basic_info` and config frames.
- **Security consequence**: Cluster configuration compromise or leakage.
- **Severity estimate**: HIGH
- **Read needed**: anatomy sufficient
- **Deepening direction**: Compare validation steps and compatibility checks between v1 and v2 paths; verify whether v1 can be triggered by negotiation in current deployments.

---

## PH-305: DNS cache poisoning via additional records (NEEDS-DEEPER)

- **Reasoning-Model**: Causal
- **Causal Test**: Confounder
- **Origin**: Cross-Model CROSS-05
- **Target**: `kong/resty/dns/client.lua:686-733` — `parseAnswer`
- **Attacker starting position**: network on-path or malicious resolver
- **Causal argument**: Safety may rely on upstream DNS resolver integrity or network trust. If external DNS components are assumed benign, the parsing logic’s lack of bailiwick/TTL enforcement becomes a confounder: the code appears safe only because the environment is trusted. If that trust fails, caching of unrelated “other” records can be abused.
- **Real risk**: Cache poisoning for unrelated names/types through additional records.
- **Attack input**: DNS response with valid answer plus additional records for unrelated domains with long TTLs.
- **Security consequence**: Traffic redirection to attacker-controlled endpoints.
- **Severity estimate**: HIGH
- **Read needed**: anatomy sufficient
- **Deepening direction**: Confirm whether `parseAnswer` caches “others” and whether bailiwick/TTL validation is enforced before inserting into cache.

---

## PH-306: HTTP/2 limit divergence between h2c and ALPN (NEEDS-DEEPER)

- **Reasoning-Model**: Causal
- **Causal Test**: Confounder
- **Origin**: Cross-Model CROSS-06
- **Target**: `kong/templates/nginx_kong.lua` — HTTP/2 enablement
- **Attacker starting position**: unauthenticated
- **Causal argument**: Enforcement of HTTP/2 limits may be provided by OpenResty/Nginx defaults or external config; the code’s safety is confounded by deployment configuration. If h2c and ALPN paths use different configs or inherit different defaults, the apparent limits are not causally tied to Lua-side routing or checks.
- **Real risk**: Header/stream DoS by choosing the weaker negotiation path.
- **Attack input**: h2c upgrade with large headers/stream concurrency exceeding ALPN limits.
- **Security consequence**: Worker exhaustion, availability degradation.
- **Severity estimate**: MEDIUM
- **Read needed**: anatomy sufficient
- **Deepening direction**: Check Nginx/OpenResty http2 settings parity for h2c vs ALPN listeners; confirm any differing limits or defaults.

---

## PH-307: WebSocket upgrade lacks Origin enforcement (NEEDS-DEEPER)

- **Reasoning-Model**: Causal
- **Causal Test**: Counterfactual
- **Origin**: Cross-Model CROSS-07
- **Target**: `kong/runloop/handler.lua:1357-1365` — WebSocket upgrade handling
- **Attacker starting position**: unauthenticated (browser-based)
- **Causal argument**: Origin checks would only trigger under adversarial cross-origin inputs; normal traffic likely does not exercise them. If no Origin validation exists at this layer, the “protection” is dormant because developers rely on upstream apps or plugins to enforce Origin. That leaves a gap if upstream assumes Kong enforces it.
- **Real risk**: CSWSH against cookie-authenticated upstreams via WS upgrade.
- **Attack input**: Cross-origin WS upgrade from attacker site to victim upstream with victim cookies.
- **Security consequence**: Unauthorized actions through hijacked WS session.
- **Severity estimate**: MEDIUM
- **Read needed**: anatomy sufficient
- **Deepening direction**: Verify whether any default or common plugins enforce WS Origin checks before `Upgrade: websocket` forwarding.

---

## Coverage Check

| Round 1+2 Finding | Intervention tested? | Counterfactual tested? | Confounder tested? | New hypothesis? |
|-------------------|:-:|:-:|:-:|:-:|
| (none) | YES | YES | YES | NO |

| Cross-Model Seed | Causal analysis done? | Hypothesis generated? |
|-----------------|:-:|:-:|
| CROSS-01 | YES | PH-301 |
| CROSS-02 | YES | PH-302 |
| CROSS-03 | YES | PH-303 |
| CROSS-04 | YES | PH-304 |
| CROSS-05 | YES | PH-305 |
| CROSS-06 | YES | PH-306 |
| CROSS-07 | YES | PH-307 |

| Trust Assumption | Confounder test done? | Hypothesis generated? |
|----------------|:-:|:-:|
| (none listed in anatomy) | YES | NO |
