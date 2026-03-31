# Round 2 Evidence

---

### PH-09: Render Endpoint Anonymous Access (Resource Exhaustion)
**Status: VALIDATED**

**Evidence:**
1. `api.go:599`: `r.Get("/render/*", ... reqSignedIn, hs.RenderHandler)` -- uses `reqSignedIn`, bypassed by anonymous auth.
2. `render.go:80-99`: Render triggers `hs.RenderService.Render()` which invokes the image renderer (headless browser or grpc call).
3. Rate limiting: `RendererConcurrentRequestLimit` defaults to 30 (`setting.go:2072`), which limits concurrent renders but doesn't prevent abuse -- 30 concurrent rendering operations is still significant resource consumption.
4. Anonymous user gets `c.GetOrgID()` and `c.GetOrgRole()` from the anonymous org config, so the render request operates in the anonymous user's org context.

**Attack**: When anonymous auth is enabled, unauthenticated users can trigger 30 concurrent rendering operations, each spawning headless browser rendering. This is a DoS vector.

**Severity**: MEDIUM (rate-limited to 30 concurrent, requires anonymous auth enabled)

---

### PH-10: Gnet Proxy Anonymous SSRF
**Status: VALIDATED (limited)**

**Evidence:**
1. `api.go:602`: `r.Any("/api/gnet/*", ... reqSignedIn, hs.ProxyGnetRequest)` -- uses `reqSignedIn`.
2. `grafana_com_proxy.go:52-57`: The proxy reads `proxyPath` from `web.Params(c.Req)["*"]` and constructs URL: `url.Path = util.JoinURLFragments(url.Path, proxyPath)`.
3. Destination is hardcoded to `GrafanaComAPIURL` (default: `https://grafana.com/api`), so this is NOT arbitrary SSRF.
4. However: the proxy injects `GrafanaComSSOAPIToken` if configured (line 44-46). If anonymous auth is enabled, unauthenticated users can make authenticated requests to grafana.com API on behalf of the Grafana instance, potentially leaking the SSO API token in request headers.
5. The proxy clears Cookie/Authorization headers from the inbound request (lines 37-39) but replaces Authorization with the Grafana.com token.

**Attack**: When anonymous auth is enabled AND a GrafanaComSSOAPIToken is configured, unauthenticated users can make requests to grafana.com API authenticated with the instance's SSO API token. This could leak the token or allow unauthorized API operations on grafana.com.

**Severity**: LOW-MEDIUM (requires anonymous auth + configured SSO token; destination is hardcoded)

---

### PH-11: K8s Snapshot DeleteKey Subresource Exposes DeleteKey to Any Reader
**Status: VALIDATED**

**Evidence:**
1. `sub_deletekey.go:55-82`: The `deletekey` subresource reads from the inner (unwrapped) storage, which retains the deleteKey.
2. `authorizer.go:32-33`: Access to the `deletekey` subresource requires `ActionSnapshotsDelete` permission only -- NO org/namespace check.
3. The underlying `SnapshotLegacyStore.Get()` at `snapshot_legacy_store.go:121-135` queries by snapshot key with NO org filter.
4. K8s namespace scoping (`NamespaceScoped() bool { return true }`) means the URL is namespace-scoped, BUT the store ignores the namespace context entirely.
5. **Critical chain**: A user with `ActionSnapshotsDelete` permission in Org-B could potentially access `GET /apis/.../namespaces/org-1/snapshots/{name}/deletekey` and retrieve the deleteKey for a snapshot in Org-A, if they know the snapshot name. The K8s API server does NOT verify that the returned object belongs to the requested namespace.

**However**: The attacker needs to know the snapshot name (key), which itself is high-entropy (32-char alphanumeric). So this is a secondary vector -- if the attacker knows the key, they can already access the snapshot via the unauthenticated REST endpoint.

**Severity**: LOW-MEDIUM (requires knowledge of snapshot key)

---

### PH-12: K8s Snapshot Standard DELETE Path Missing Org Check
**Status: VALIDATED**

**Evidence:**
1. `snapshot_legacy_store.go:60-83`: The `Delete` function fetches snapshot by key (name) with `GetDashboardSnapshotQuery{Key: name}` -- NO org filter.
2. `database.go:89-108`: The underlying DB query uses `sess.Get(&snapshot)` with only the Key field -- queries across all orgs.
3. After fetching, it deletes via `DeleteDashboardSnapshotCommand{DeleteKey: snap.DeleteKey}` -- the DELETE SQL at `database.go:83` is `DELETE FROM dashboard_snapshot WHERE delete_key=?` -- also no org filter.
4. K8s namespace scoping in the URL path does NOT translate to an org filter in the store query.
5. **Contrast with REST API**: `DeleteDashboardSnapshot()` at `dashboard_snapshot.go:218` checks `queryResult.OrgID != c.OrgID`.
6. This is the same class of vulnerability as PH-01 but via the standard K8s DELETE path (not the delete-by-deleteKey custom route).

**Attack chain**: User in Org-B with `ActionSnapshotsDelete` and knowledge of a snapshot key (32-char, high entropy) can delete a snapshot belonging to Org-A via `DELETE /apis/.../namespaces/org-B-ns/snapshots/{name}`.

**Severity**: MEDIUM (requires knowledge of snapshot key -- same entropy barrier as PH-01)

---

### PH-13: K8s Snapshot GET Path Cross-Org Read
**Status: VALIDATED**

**Evidence:**
1. `snapshot_legacy_store.go:121-135`: The `Get` function queries by key without org filter.
2. `storage_without_create.go:51-57`: The wrapper strips deleteKey and dashboard from the response, so sensitive data is protected.
3. However, metadata (name, created time, expiry, external flag) is still returned.
4. K8s namespace scoping does NOT prevent cross-org reads at the store level.

**Attack**: User in Org-B with `ActionSnapshotsRead` can read snapshot metadata from Org-A if they know the key. Dashboard content is stripped, so this is limited to metadata leakage.

**Severity**: LOW (metadata only, requires high-entropy key knowledge)

---

### PH-14: Test Receiver Error Message Contains Webhook URL with Secret
**Status: NEEDS-DEEPER**

**Evidence:**
1. `api_alertmanager.go:312-333`: Error strings from test results are passed through directly to the API response at line 327: `configs[jx].Error = config.Error`.
2. `testreceivers.go:15-49`: The test function passes settings (including secrets) to the alerting library's `TestReceivers`.
3. The alerting library constructs HTTP requests with the actual secret values (e.g., VictorOps URL, API keys) and if the request fails, typical Go HTTP errors include the URL (e.g., "Post \"https://secret-url.example.com/api\": dial tcp: ...").
4. The error string is not sanitized or redacted before being returned to the caller.

**What's needed**: Access to the `github.com/grafana/alerting` library source to confirm error message format. Based on standard Go HTTP client behavior, errors from `http.Client.Do()` include the URL, which would contain the secret VictorOps URL.

**Severity**: MEDIUM (likely, pending confirmation of external library behavior)
