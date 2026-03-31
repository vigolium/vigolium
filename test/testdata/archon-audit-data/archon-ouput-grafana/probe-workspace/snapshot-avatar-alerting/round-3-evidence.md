# Round 3 Evidence

---

### PH-15: External Snapshot Delete SSRF via Stored URL
**Status: VALIDATED (limited exploitability)**

**Evidence:**
1. `service.go:149-179`: `DeleteExternalDashboardSnapshot(externalUrl string)` performs `client.Get(externalUrl)` with no URL validation -- no check for internal IPs, no protocol restriction.
2. The `externalUrl` comes from the database field `ExternalDeleteURL` which is set at `service.go:86` from the external snapshot server's response.
3. The external snapshot server URL is admin-configured via `ExternalSnapshotUrl` in grafana.ini.
4. Attack vector: If the external snapshot server is compromised or misconfigured to return a crafted `DeleteUrl` (e.g., `http://169.254.169.254/latest/meta-data/`), then when any user deletes that snapshot, the Grafana server makes an HTTP GET to the internal/cloud metadata endpoint.
5. The HTTP GET response is NOT returned to the caller (only status code is checked), limiting data exfiltration.
6. However, the request reaches internal endpoints, enabling:
   - Cloud metadata access (AWS/GCP/Azure credential theft if response handling changes)
   - Internal service port scanning (via error messages/timing)
   - Triggering actions on internal services via GET requests

**Exploitability limitations**: Requires compromised external snapshot server OR admin misconfiguration. The attacker cannot directly control `ExternalDeleteURL` via API.

**Severity**: LOW-MEDIUM (requires external server compromise; response not returned to attacker)

---

### PH-16: K8s Snapshot Legacy Store Delete Has No Org Filter (Amplified SSRF)
**Status: VALIDATED**

**Evidence:**
1. `snapshot_legacy_store.go:60-83`: Delete fetches by key without org filter, then calls `dashboardsnapshots.DeleteExternalDashboardSnapshot(snap.ExternalDeleteURL)` if the snapshot is external.
2. Combined with PH-15: A user in Org-B who knows a snapshot key from Org-A can trigger the K8s DELETE, which:
   a. Fetches the snapshot from ANY org (no org filter)
   b. Calls `DeleteExternalDashboardSnapshot()` with the stored URL
   c. Deletes the snapshot from the database
3. This means the cross-org delete vulnerability (PH-01/PH-12) also amplifies SSRF if the target snapshot was external.

**Severity**: MEDIUM (combines cross-org delete with SSRF, but requires knowing snapshot key)

---

### PH-17: SnapshotPublicMode Full Unauthenticated Chain
**Status: VALIDATED (by design, but with risk)**

**Evidence:**
1. `auth.go:238-251`: `SnapshotPublicModeOrCreate` allows unauthenticated POST when SnapshotPublicMode=true.
2. `service.go:86-88`: In the REST API, external snapshot creation path sets `cmd.ExternalDeleteURL = resp.DeleteUrl`. However, the public mode function `CreateDashboardSnapshotPublic` at `service.go:111-129` only supports LOCAL snapshots -- it calls `PrepareLocalSnapshot` directly without external path.
3. External snapshots are NOT available in public mode because `CreateDashboardSnapshotPublic` doesn't handle the `cmd.External` flag.
4. However, in non-public mode via the standard `CreateDashboardSnapshot` at `dashboard_snapshot.go:72-100`, the `cmd.External` flag from user input IS checked (line 76) and external creation is allowed.
5. In public mode, the full lifecycle is unauthenticated by design for shareability.

**Severity**: LOW (by design; external snapshots not available in public mode)

---

### PH-18: K8s Snapshot List Is Org-Scoped (Correctly)
**Status: INVALIDATED**

**Evidence:**
1. `snapshot_legacy_store.go:85-119`: List uses `request.OrgIDForList(ctx)` which correctly extracts org ID from namespace context.
2. `namespace.go:40-51`: `OrgIDForList` parses the namespace from K8s context and extracts OrgID.
3. The `SearchDashboardSnapshots` query at `snapshot_legacy_store.go:101-106` passes `OrgID: orgId`, which is correctly scoped.
4. List IS properly org-scoped, unlike Get/Delete.

**Severity**: N/A (correctly implemented)
