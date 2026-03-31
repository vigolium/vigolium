# Cross-Model Seeds: core-probe

## CROSS-01: HTTP/2 normalization mismatch -> route/auth bypass

Source-A: PH-01 from backward-reasoner (round-1-hypotheses.md)
Source-B: PH-01 from contradiction-reasoner (round-2-hypotheses.md)
Connection: Same target (`kong/router/utils.lua:57-64`) and same trust boundary (HTTP/2 entry path normalization vs Lua normalization used for routing).
Combined hypothesis: HTTP/2 `:path` normalization differs from `normalize(req_uri, true)` causing route misclassification and auth plugin bypass for encoded dot/ slash sequences.
Test direction for causal-verifier: Compare `var.request_uri` for h2c vs ALPN with encoded `%2f/%2e` sequences and confirm router match vs upstream canonicalization.

## CROSS-02: External plugin RPC post-auth mutation

Source-A: PH-03 from backward-reasoner (round-1-hypotheses.md)
Source-B: PH-02 from contradiction-reasoner (round-2-hypotheses.md)
Connection: Same boundary (external plugin RPC to PDK) and same effect (auth context mutation after validation).
Combined hypothesis: A compromised external plugin server can issue PDK calls to alter consumer/auth headers after JWT/OAuth2 runs, bypassing auth decisions.
Test direction for causal-verifier: Identify PDK methods exposed to external plugins and verify if calls like `kong.client.authenticate` or header setters can run after auth plugins in request phase.

## CROSS-03: RPC oversized frame DoS

Source-A: PH-04 from backward-reasoner (round-1-hypotheses.md)
Source-B: PH-03 from contradiction-reasoner (round-2-hypotheses.md)
Connection: Same RPC framing paths (`pb_rpc.read_frame` / MsgPack unpacking) with missing size limits.
Combined hypothesis: Length-prefixed or MsgPack frames without Lua-level size caps allow oversized payloads that exhaust memory or block worker event loop.
Test direction for causal-verifier: Trace socket receive calls and check for any max payload limits or upstream `lua_socket` constraints; validate failure mode on large advertised sizes.

## CROSS-04: CP/DP legacy sync fallback validation gap

Source-A: PH-05 from backward-reasoner (round-1-hypotheses.md)
Source-B: PH-04 from contradiction-reasoner (round-2-hypotheses.md)
Connection: Same boundary (CP/DP WebSocket sync) and same gap (sync v1 fallback parity with v2).
Combined hypothesis: Forcing sync v1 (via capability omission/older version) yields weaker validation, enabling config poisoning or config exfiltration to a fake DP.
Test direction for causal-verifier: Compare v1 vs v2 validation for `basic_info` and config payload handling; confirm if v1 can be triggered by protocol negotiation.

## CROSS-05: DNS cache poisoning via additional records

Source-A: PH-06 from backward-reasoner (round-1-hypotheses.md)
Source-B: PH-05 from contradiction-reasoner (round-2-hypotheses.md)
Connection: Same target (`parseAnswer`) and same trust boundary (DNS response parsing/caching).
Combined hypothesis: `parseAnswer` caches non-requested records (others) enabling cache poisoning with unrelated names/types from a single response.
Test direction for causal-verifier: Verify caching of “others” records and whether bailiwick/TTL validation is enforced before cache insert.

## CROSS-06: HTTP/2 limit enforcement divergence (ALPN vs h2c)

Source-A: PH-07 from backward-reasoner (round-1-hypotheses.md)
Source-B: PH-06 from contradiction-reasoner (round-2-hypotheses.md)
Connection: Same surface (HTTP/2 enablement/limits) and same divergence concern (h2c vs ALPN paths).
Combined hypothesis: HTTP/2 limits enforced inconsistently between h2c upgrade and ALPN paths, enabling header/stream DoS under certain negotiation paths.
Test direction for causal-verifier: Identify HTTP/2 configuration settings in templates and verify parity of limits for h2c vs ALPN in deployed OpenResty/Nginx.

## CROSS-07: WebSocket upgrade lacks Origin validation

Source-A: PH-02 from backward-reasoner (round-1-hypotheses.md)
Source-B: PH-08 from contradiction-reasoner (round-2-hypotheses.md)
Connection: Same code path (`kong/runloop/handler.lua:1357-1365`) and same missing check (Origin validation on upgrade).
Combined hypothesis: WebSocket upgrades are proxied without Origin allowlist checks, enabling CSWSH against cookie-authenticated upstreams.
Test direction for causal-verifier: Confirm no default/plugin-based Origin checks run before upgrade; assess whether standard configurations include WS Origin enforcement.
