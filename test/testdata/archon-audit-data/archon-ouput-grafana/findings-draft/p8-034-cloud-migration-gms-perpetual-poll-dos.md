Phase: 10
Sequence: 034
Slug: cloud-migration-gms-perpetual-poll-dos
Verdict: VALID
Rationale: An attacker-controlled GMS server can maintain a snapshot in `PROCESSING` state indefinitely by returning the `PROCESSING` state on every `GetSnapshotStatus` poll, causing `syncSnapshotStatusFromGMSUntilDone` to run a persistent background goroutine that issues authenticated HTTP requests to the attacker's server every 10 seconds with no timeout or iteration cap.
Severity-Original: MEDIUM
PoC-Status: theoretical
Origin-Finding: security/findings-draft/p8-020-cloud-migration-attacker-controlled-encryption-key.md
Origin-Pattern: AP-020

## Summary

After a snapshot is uploaded, Grafana launches `syncSnapshotStatusFromGMSUntilDone` as a background goroutine triggered by any call to `GetSnapshot`. This goroutine polls GMS every 10 seconds via `GetSnapshotStatus` until the snapshot reaches a terminal state (`FINISHED`, `CANCELED`, or `ERROR`). The loop termination condition is controlled by the GMS response — if an attacker-controlled GMS server continually returns `PROCESSING` or `INITIALIZED`, the goroutine runs indefinitely.

```go
// cloudmigration.go:677-693
tick := time.NewTicker(10 * time.Second)
defer tick.Stop()

for snapshot.ShouldQueryGMS() {    // terminates only when GMS says FINISHED/CANCELED/ERROR
    select {
    case <-ctx.Done():
        return
    case <-tick.C:
        updatedSnapshot, _ := syncStatus(ctx, session, snapshot)
        snapshot = updatedSnapshot
    }
}
```

The goroutine context (`asyncSyncCtx`) is derived from the request span context without any deadline:
```go
asyncSyncCtx := trace.ContextWithSpanContext(context.Background(), span.SpanContext())
go s.syncSnapshotStatusFromGMSUntilDone(asyncSyncCtx, session, snapshot, syncStatus)
```

The only cancellation path is via `s.cancelFunc()` which is the same global cancel function used by snapshot creation/upload goroutines. If the cancel function is not set (no active build/upload), the polling goroutine has no external cancellation signal.

Each poll sends an authenticated HTTP GET request to the GMS server (including `Authorization: Bearer <stackID>:<authToken>` headers). With an attacker-controlled GMS server, this means:
1. The attacker receives an authenticated request from Grafana every 10 seconds, forever
2. The goroutine holds a reference to the session object (including the `AuthToken`) for the duration
3. Each poll issues an HTTP request from Grafana's server, creating persistent outbound connections to the attacker

Additionally, `syncSnapshotStatusFromGMSUntilDone` uses an atomic flag `isSyncSnapshotStatusFromGMSRunning` to prevent multiple concurrent polling loops, but a second `GetSnapshot` call while a loop is running silently discards the request. The polling loop thus occupies Grafana's single migration goroutine slot indefinitely, preventing legitimate status synchronization.

## Location

- **Poll loop**: `pkg/services/cloudmigration/cloudmigrationimpl/cloudmigration.go:643-694` -- `syncSnapshotStatusFromGMSUntilDone` with 10-second ticker and no upper iteration bound
- **Termination condition**: `pkg/services/cloudmigration/model.go:161-163` -- `ShouldQueryGMS()` returns `true` for `SnapshotStatusPendingProcessing` or `SnapshotStatusProcessing` (attacker-controlled via GMS state)
- **Context without deadline**: `pkg/services/cloudmigration/cloudmigrationimpl/cloudmigration.go:632` -- `asyncSyncCtx := trace.ContextWithSpanContext(context.Background(), span.SpanContext())` -- `context.Background()` has no deadline
- **HTTP request per poll**: `pkg/services/cloudmigration/gmsclient/gms_client.go:151-186` -- `GetSnapshotStatus` sends HTTP GET with auth header per invocation
- **Auth token in request**: `pkg/services/cloudmigration/gmsclient/gms_client.go:157` -- `req.Header.Set("Authorization", fmt.Sprintf("Bearer %d:%s", session.StackID, session.AuthToken))`
- **No maximum poll count**: No `maxAttempts` counter, no deadline, no TTL on the snapshot polling lifecycle

## Attacker Control

- **State returned**: Attacker's GMS server returns `{"state": "PROCESSING", "results": []}` on every poll. `gmsStateToLocalStatus["PROCESSING"] = SnapshotStatusProcessing`, so `ShouldQueryGMS()` remains `true` and the loop continues.
- **Poll frequency**: Fixed at 10 seconds by Grafana's `time.NewTicker`. The attacker receives approximately 8,640 authenticated requests per day per polling loop.
- **Trigger**: Any call to `GET /api/cloudmigration/migration/:uid/snapshot/:snapshotUid` while snapshot is in `pending_processing` or `processing` state triggers the polling goroutine. Since the goroutine is singleton (atomic flag), repeated `GetSnapshot` calls do not create multiple loops, but a single snapshot can sustain one perpetual loop.
- **Authentication required**: GrafanaAdmin + `cfg.CloudMigration.Enabled = true`.

## Trust Boundary Crossed

TB-8 (Cloud Migration external control plane) to TB-1 (Internet edge, persistent outbound). An attacker-controlled GMS server maintains a persistent authenticated connection from Grafana's server to the attacker's infrastructure without any time bound.

## Impact

- **Credential harvesting over time**: Each poll includes the `Authorization: Bearer <stackID>:<authToken>` header. The attacker accumulates a log of Grafana-to-GMS auth tokens for ongoing use.
- **Persistent SSRF beacon**: Grafana sends an HTTP GET to the attacker's server every 10 seconds for the lifetime of the Grafana process, confirming Grafana's IP address, availability, and the auth token.
- **Resource goroutine exhaustion**: The `isSyncSnapshotStatusFromGMSRunning` atomic flag prevents more than one polling loop at a time. A perpetually-polling snapshot blocks all future status synchronization for any snapshot in the instance.
- **Connection pool pressure**: With multiple sessions each having a perpetual poller, the Grafana HTTP client pool is continuously occupied with outbound connections to the attacker.
- **Process lifetime persistence**: The polling goroutine runs until the Grafana process restarts or `CancelSnapshot` is called. There is no automatic expiration.
- **Severity**: MEDIUM -- requires SSRF prerequisite (p7-021) and a completed snapshot upload, but creates a persistent outbound channel to the attacker's infrastructure with no automatic timeout.

## Evidence

```go
// model.go:161-163 -- termination controlled by GMS state
func (s CloudMigrationSnapshot) ShouldQueryGMS() bool {
    return s.Status == SnapshotStatusPendingProcessing || s.Status == SnapshotStatusProcessing
}
// Attacker keeps returning PROCESSING state -> ShouldQueryGMS() == true forever

// cloudmigration.go:632 -- no deadline on polling context
asyncSyncCtx := trace.ContextWithSpanContext(context.Background(), span.SpanContext())
// context.Background() has no cancellation or deadline

// cloudmigration.go:677-693 -- unbounded polling loop
tick := time.NewTicker(10 * time.Second)  // 8640 requests/day
for snapshot.ShouldQueryGMS() {           // attacker controls this condition
    select {
    case <-ctx.Done(): return             // only cancelled if CancelSnapshot called
    case <-tick.C:
        syncStatus(ctx, session, snapshot) // HTTP GET to attacker's server every 10s
    }
}

// gms_client.go:157 -- auth token included in each poll
req.Header.Set("Authorization", fmt.Sprintf("Bearer %d:%s", session.StackID, session.AuthToken))
```

**No upper bound exists:**
- No `maxAttempts` counter
- No polling TTL / snapshot processing deadline
- No HTTP client timeout specific to polling (uses `cfg.CloudMigration.GMSGetSnapshotStatusTimeout` per individual request, but not per total polling lifetime)

## Reproduction Steps

1. Set up Grafana with `cfg.CloudMigration.Enabled = true`
2. Complete a snapshot creation and upload using attacker's GMS server (per p8-020 attack chain)
3. Configure attacker's GMS server to respond to all `GET /cloud-migrations/api/v1/snapshots/*/status` requests with: `{"state":"PROCESSING","results":[]}`
4. As GrafanaAdmin, call `GET /api/cloudmigration/migration/:uid/snapshot/:snapshotUid` once
5. Observe: Grafana initiates a background polling goroutine
6. After 24 hours, attacker's server log shows ~8,640 authenticated GET requests from Grafana
7. The goroutine continues indefinitely until Grafana is restarted or `CancelSnapshot` is explicitly called
8. Calling `CancelSnapshot` on a cross-org snapshot (per p8-003) allows a different attacker admin to terminate the loop
