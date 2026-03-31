Phase: 10
Sequence: 063
Slug: scanner-credential-in-scan-job-queue
Verdict: VALID
Rationale: When a scan job is launched, the scanner Registration struct (including plaintext access_credential) is serialized to JSON via ToJSON() and stored as the "registration" job parameter in Redis, exposing scanner adapter credentials to anyone with Redis read access.
Severity-Original: HIGH
PoC-Status: theoretical
PoC-Block-Reason: Requires running Harbor instance with configured scanner registration and active scan job; code path analysis confirms the vulnerability through direct tracing of serialization to Redis storage.
Origin-Finding: security/findings-draft/p8-026-redis-plaintext-credentials.md
Origin-Pattern: AP-026

## Summary

During scan job creation in `src/controller/scan/base_controller.go:944`, `param.Registration.ToJSON()` serializes the complete `scanner.Registration` struct — including the `AccessCredential` field — as a JSON string and stores it in the `registration` job parameter in Redis. Unlike the replication credential case (p8-026), there is no decryption step because scanner credentials are not encrypted at rest in the database (they are stored as-is in `scanner_registration.access_cred`). The credential appears in Redis job params as plaintext for the duration of any active scan job. This pattern is structurally identical to AP-026 (plaintext credentials in job queue).

## Location

- `src/controller/scan/base_controller.go:944` -- `rJSON, err := param.Registration.ToJSON()` serializes full Registration
- `src/controller/scan/base_controller.go:967` -- `params[sca.JobParamRegistration] = rJSON` stores JSON including `access_credential` in Redis
- `src/pkg/scan/dao/scanner/model.go:51` -- `AccessCredential string json:"access_credential,omitempty"` -- included in JSON serialization

## Attacker Control

- Any actor with Redis read access (no authentication required in default Harbor deployments)
- Credentials present for all active and queued scan jobs
- Container compromise on Docker network provides Redis access
- Scan jobs run on every artifact push if auto-scan is enabled, keeping the credential perpetually present

## Trust Boundary Crossed

- TB-4: Core/Controller to Redis (no authentication by default)
- Scanner adapter credentials cross from DB storage to plaintext JSON in Redis

## Impact

- Exfiltration of scanner adapter credentials (API keys, Basic auth passwords) from Redis
- Credentials valid for direct access to vulnerability scanner adapters (Trivy, Clair, etc.)
- If auto-scan is enabled, credential is continuously present in Redis for any queued scan
- Unlike p8-026 (replication), scanner credentials are NOT encrypted at rest in DB, making this the primary exposure path

## Evidence

- `base_controller.go:944`: `rJSON, err := param.Registration.ToJSON()` -- calls `json.Marshal(r)` which includes all exported fields
- `base_controller.go:967`: `params[sca.JobParamRegistration] = rJSON` -- stored directly as Redis job param
- `job.go:170`: `printJSONParameter(JobParamRegistration, removeRegistrationAuthInfo(r), myLogger)` -- note: log printing DOES redact, but Redis storage (line 967) does not
- `job.go:428`: `AccessCredential: "[HIDDEN]"` in `removeRegistrationAuthInfo` confirms developer awareness but does not protect Redis storage path

## Reproduction Steps

1. Configure a scanner registration with credentials (e.g., Basic auth)
2. Enable auto-scan or manually trigger a scan via `POST /api/v2.0/projects/{name}/repositories/{repo}/artifacts/{digest}/scan`
3. Connect to Redis: `redis-cli -h <harbor-redis>`
4. List job keys: `KEYS *` or `SMEMBERS known_job_types`
5. Read scan job parameters containing the `registration` key
6. Extract plaintext `access_credential` from the JSON value
