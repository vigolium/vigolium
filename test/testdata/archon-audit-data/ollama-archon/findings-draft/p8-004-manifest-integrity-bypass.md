Phase: 8
Sequence: 004
Slug: manifest-integrity-bypass
Verdict: VALID
Rationale: Neither old nor new registry client verifies Docker-Content-Digest header on manifest responses. Combined with HTTP pull path that bypasses insecure flag check, MITM manifest substitution is practical. Advocate confirmed blob-level verification does not protect the manifest itself.
Severity-Original: HIGH
PoC-Status: pending
Pre-FP-Flag: none
Debate: archon/chamber-workspace/chamber-A/debate.md

## Summary

The Ollama client does not verify the Docker-Content-Digest response header when pulling manifests from a registry. Both the legacy path (`pullModelManifest` in server/images.go) and the new registry client path acknowledge this omission (TODO comment at registry.go:800). When combined with the HTTP pull path via registry.Local (which accepts `http://` scheme without requiring the insecure flag), a network MITM attacker can substitute the manifest body to redirect blob downloads to malicious content or inject an Entrypoint field in the config blob.

## Location

- `server/images.go:835-857` -- pullModelManifest: no Docker-Content-Digest verification
- `server/images.go:846` -- io.ReadAll(resp.Body) with no digest comparison
- `server/internal/client/ollama/registry.go:800` -- `// TODO(bmizerany): return digest here`
- `server/internal/client/ollama/registry.go:786-789` -- manifest fetch (no digest verification)

## Attacker Control

Full control over manifest body via MITM:
- Layer digest replacement (redirect to pre-uploaded malicious blobs)
- Config blob digest replacement (inject Entrypoint, MCP commands)
- Layer removal (produce incomplete models)
- Media type manipulation

## Trust Boundary Crossed

Network transport (MITM position) to local model integrity. The manifest is the trust anchor for the entire model -- without manifest verification, all per-blob SHA-256 checks are meaningless because the attacker controls which digests are expected.

## Impact

- Supply-chain RCE via config blob Entrypoint injection
- GGUF parser exploitation via redirected layer blobs
- Model integrity violation (wrong weights loaded)
- Combines with HTTP-without-insecure-flag (registry.Local path) for practical exploitation

## Evidence

1. `server/images.go:846`: `data, err := io.ReadAll(resp.Body)` -- raw body read, no digest check
2. `server/images.go:852`: `json.Unmarshal(data, &m)` -- direct parse without verification
3. `server/internal/client/ollama/registry.go:800`: TODO comment acknowledging the omission
4. Blob-level verification at `server/images.go:639-654` verifies SHA-256 per-blob, but the manifest tells the client WHICH digests to expect -- attacker controls the expectation
5. HTTP pull via registry.Local path does not require insecure flag (Team-01 PH-15)

## Reproduction Steps

1. Set up a MITM proxy on the network path between Ollama client and a custom registry
2. Create a legitimate model on the custom registry
3. Prepare a malicious manifest that swaps the config blob digest to point to an attacker-crafted config with Entrypoint
4. Upload the malicious config blob to the registry (it will have its own valid sha256 digest)
5. When the client pulls the model, intercept the manifest response and substitute with the malicious manifest
6. The client accepts the substituted manifest (no Docker-Content-Digest verification)
7. The client downloads blobs matching the attacker's manifest -- including the malicious config
8. `ollama run <model>` triggers the injected Entrypoint
