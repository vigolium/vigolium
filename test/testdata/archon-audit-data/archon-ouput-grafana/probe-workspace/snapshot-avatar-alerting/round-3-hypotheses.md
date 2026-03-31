# Round 3 Hypotheses

## Focus: External snapshot SSRF, K8s snapshot legacy store org isolation, SnapshotPublicMode full chain

---

### PH-15: External Snapshot Delete SSRF via Stored URL
**Hypothesis**: When deleting a snapshot that was created as an external snapshot, the stored `ExternalDeleteURL` from the database is used to make an HTTP GET request without URL validation. If the external snapshot server returns a crafted `DeleteUrl`, the delete operation triggers SSRF to arbitrary endpoints.
**Test**: Check if `ExternalDeleteURL` is validated before HTTP GET. Check if external snapshot server response is validated.

### PH-16: K8s Snapshot Legacy Store Delete Has No Org Filter
**Hypothesis**: The K8s standard DELETE at `snapshot_legacy_store.go:60-83` fetches snapshot by key with no org filter, then triggers `DeleteExternalDashboardSnapshot(snap.ExternalDeleteURL)` if the snapshot was external. This means cross-org delete also triggers a GET to the external snapshot's delete URL, potentially amplifying SSRF.
**Test**: Confirm the Delete function at snapshot_legacy_store.go:60 has no org filter.

### PH-17: SnapshotPublicMode Full Unauthenticated Chain
**Hypothesis**: When SnapshotPublicMode is enabled:
1. Unauthenticated POST to /api/snapshots/ (reqSnapshotPublicModeOrCreate passes)
2. No user context, no RBAC, no dashboard validation
3. Unauthenticated GET to /api/snapshots/:key (always unauthenticated)
4. Unauthenticated DELETE via /api/snapshots-delete/:deleteKey (reqSnapshotPublicModeOrDelete passes)
The full lifecycle is unauthenticated, and external snapshots can be created with attacker-controlled ExternalDeleteURL.
**Test**: Check if external snapshots are allowed in public mode.

### PH-18: K8s Snapshot List Leaks Cross-Org Metadata
**Hypothesis**: The K8s List at snapshot_legacy_store.go:85-119 uses `request.OrgIDForList(ctx)` which should extract org from namespace context. This means List is org-scoped. Verify that this is correct and the org isolation holds for List.
**Test**: Check OrgIDForList implementation.
