Phase: 8
Sequence: 026
Slug: redis-plaintext-credentials
Verdict: VALID
Rationale: Registry credentials are decrypted from DB and serialized as plaintext JSON into Redis job queue parameters during replication; any actor with Redis read access can extract all active replication credentials. Redis has no authentication by default in many Harbor deployments.
Severity-Original: HIGH
PoC-Status: theoretical
Pre-FP-Flag: none
Debate: security/chamber-workspace/chamber-02/debate.md

Adversarial-Verdict: CONFIRMED
Adversarial-Rationale: Code path from fromDaoModel decrypt (manager.go:238) through json.Marshal (copy.go:125) to Redis job queue is unconditional with no credential scrubbing; AccessSecret has json:"access_secret" tag enabling full serialization; default Redis has no authentication.
Severity-Final: MEDIUM
PoC-Status: theoretical

## Summary

During replication job creation, Harbor decrypts registry credentials (AccessSecret) from the database using `ReversibleEncrypt` and serializes the entire resource model (including plaintext credentials) as JSON into Redis job parameters. The credentials remain in plaintext in Redis for the duration of the job's lifecycle. Given that Redis often has no authentication in default Harbor deployments and is accessible from the internal Docker network, any container compromise or network-adjacent attacker can extract all registry credentials for pending and active replication jobs.

## Location

- `src/controller/replication/flow/copy.go:125-144` -- Job parameter serialization with plaintext credentials
- `src/pkg/reg/manager.go:218-249` -- `fromDaoModel` decrypts AccessSecret from DB
- Redis job queue: `src_resource` parameter contains full JSON including `Credential.AccessSecret`

## Attacker Control

- Any actor with Redis read access (no authentication required in default deployments)
- Credentials are present for all active/pending replication jobs
- Container compromise on the same Docker network provides Redis access

## Trust Boundary Crossed

- TB-4: Core API to Redis (no authentication by default)
- Encrypted credentials in PostgreSQL cross to plaintext in Redis

## Impact

- Exfiltration of all registry credentials for active replication targets
- Credentials stored as long as replication jobs remain in queue (potentially hours/days)
- Enables unauthorized access to all configured remote registries

## Evidence

- Deep Probe PH-C08: Validated via causal reasoning
- copy.go:125-144: `json.Marshal(srcResource)` includes decrypted AccessSecret
- manager.go:218-249: `fromDaoModel` decrypts credentials before job serialization
- Redis default config: no `requirepass` in many Harbor deployments

## Reproduction Steps

1. Configure a replication policy with registry credentials
2. Trigger a replication job (manual or automatic)
3. Connect to Redis (default: `redis-cli -h <harbor-redis>`)
4. Read job parameters: `HGETALL` on replication job keys
5. Extract plaintext credentials from `src_resource` JSON parameter

## Adversarial Review Notes

- **Severity downgraded from HIGH to MEDIUM**: Exploitation requires internal Docker network access (container compromise or misconfigured network). Redis is not exposed externally by default.
- **Code path fully confirmed**: The decryption-to-serialization path is unconditional with zero sanitization.
- **Both src and dst credentials exposed**: Both `src_resource` and `dst_resource` job parameters contain full registry credentials.
- **Full review**: security/adversarial-reviews/redis-plaintext-credentials-review.md
