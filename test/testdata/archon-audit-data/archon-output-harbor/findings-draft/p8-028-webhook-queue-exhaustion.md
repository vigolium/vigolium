Phase: 8
Sequence: 028
Slug: webhook-queue-exhaustion
Verdict: VALID
Rationale: No per-project webhook policy count limit combined with MaxCurrency=0 (no per-type concurrency cap) and ShouldRetry=true enables a project-admin to flood the shared job queue, starving replication, scanning, and GC jobs across all tenants.
Severity-Original: MEDIUM
PoC-Status: theoretical
Pre-FP-Flag: none
Debate: security/chamber-workspace/chamber-02/debate.md

## Summary

Harbor's webhook system has no per-project limit on the number of webhook policies that can be created. Each Harbor event (artifact push, pull, delete) generates one job per matching policy. The WebhookJob declares `MaxCurrency() = 0` (unlimited per-type concurrency in gocraft/work) and `ShouldRetry() = true` with `MaxFails = 3`. A project-admin can create hundreds of policies, causing each event to generate hundreds of jobs competing for the shared worker pool (default 10 workers), starving critical jobs like replication, scanning, and garbage collection.

## Location

- `src/controller/webhook/controller.go:84-86` -- `CreatePolicy` with no policy count limit
- `src/jobservice/job/impl/notification/webhook_job.go:53-55` -- `MaxCurrency() = 0`
- `src/jobservice/job/impl/notification/webhook_job.go:38-50` -- `ShouldRetry() = true`, `MaxFails = 3`
- `src/jobservice/worker/cworker/c_worker.go:431-443` -- `MaxConcurrency: 0` means unlimited in gocraft/work

## Attacker Control

- Project-admin creates unlimited webhook policies (no count cap)
- Policies subscribed to all event types multiply job generation
- Slow/non-responsive endpoint targets maximize worker hold time (up to HTTP timeout)

## Trust Boundary Crossed

- Project-admin privilege escalates to cross-tenant denial of service
- Single project's webhooks starve all other projects' job processing

## Impact

- Job queue flooding: hundreds of webhook jobs per event
- Worker pool starvation: replication, scanning, GC blocked
- Cross-tenant DoS: one project affects all others
- Recovery requires manual policy deletion

## Evidence

- Tracer confirmed: no policy count check in controller.go:84-86
- MaxCurrency=0 at webhook_job.go:53-55 confirmed (contrast: SlackJob MaxCurrency=1)
- Worker pool bounded at WORKER_POOL_SIZE (default 10) provides natural throttle but enables starvation
- Deep Probe PH-17: NEEDS-DEEPER, now resolved

## Reproduction Steps

1. Authenticate as project-admin
2. Create 100 webhook policies: `POST /api/v2.0/projects/{id}/webhook/policies` each subscribed to all event types
3. Push an artifact to the project
4. Observe job service queue: 100+ webhook jobs queued per event
5. Monitor other projects' replication/scanning jobs being delayed or timed out
