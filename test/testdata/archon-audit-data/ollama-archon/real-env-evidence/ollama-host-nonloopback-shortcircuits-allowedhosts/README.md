Evidence for adversarial cold verification of p8-060.

Server built at commit 57653b8e (current HEAD on local checkout) using `go build .`.

Two runs:
1. OLLAMA_HOST=0.0.0.0:21437 (non-loopback bind) — attack traffic with Host: evil.attacker.example
   - me-attack.out: POST /api/me (401 with ed25519 pubkey embedded in signin_url base64 payload)
   - tags-attack.out: GET /api/tags (200 models listing)
   - generate-attack.out: POST /api/generate (404 model-not-found — i.e., handler executed)
   The allowedHostsMiddleware short-circuited at server/routes.go:1615 for every request.

2. OLLAMA_HOST=127.0.0.1:21438 (loopback bind) — control
   - me-loopback.out: POST /api/me with Host: evil.attacker.example → 403 (blocked)
   - tags-loopback.out: GET /api/tags with Host: evil.attacker.example → 403 (blocked)
   - Host: 127.0.0.1:21438 still accepted (200) — shows filter is working correctly on loopback.

Contrast confirms the short-circuit at server/routes.go:1615-1618 is the sole difference: when addr.Addr() is non-loopback (0.0.0.0, LAN IP), the host-header DNS-rebinding filter is waived.

Decoded base64 in the /api/me signin_url response is the victim's real ssh-ed25519 public key — disclosed to any LAN client sending an unauthenticated POST.
