# Round 2 Hypotheses

## Focus: Deepening on reqSignedIn bypass for render/gnet, K8s snapshot deleteKey subresource auth, K8s snapshot namespace scoping

---

### PH-09: Render Endpoint Anonymous Access (Resource Exhaustion)
**Hypothesis**: `/render/*` uses `reqSignedIn`, so anonymous users can trigger rendering operations when anonymous auth is enabled. Rendering is resource-intensive (spawns browser/renderer process). This could be used for DoS.
**Test**: Check if render path has any additional auth beyond reqSignedIn. Check for rate limiting.

### PH-10: Gnet Proxy Anonymous SSRF
**Hypothesis**: `/api/gnet/*` uses `reqSignedIn`, so anonymous users can proxy requests through Grafana to grafana.com. The proxy path is attacker-controlled (`web.Params(c.Req)["*"]`). This could be used for SSRF scanning via the Grafana server.
**Test**: Check if the proxy destination is hardcoded or influenced by the path parameter. Check if `GrafanaComAPIToken` is injected (credential leakage to anonymous users).

### PH-11: K8s Snapshot DeleteKey Subresource Exposes DeleteKey to Any Reader
**Hypothesis**: The `deletekey` subresource at `sub_deletekey.go:55-82` exposes the deleteKey to any user with `ActionSnapshotsDelete` permission. Combined with the K8s RBAC authorizer (authorizer.go:32-33), a user in Org-B can retrieve the deleteKey of a snapshot from Org-A (since namespace scoping may not be enforced).
**Test**: Determine if K8s namespace scoping enforces org isolation for the deletekey subresource.

### PH-12: K8s Snapshot Standard DELETE Path Missing Org Check
**Hypothesis**: The K8s standard DELETE path (via storageWrapper.Delete at storage_without_create.go:65-67) delegates to the inner storage. Does the K8s namespace scoping enforce that a user can only delete snapshots within their own namespace/org?
**Test**: Check if the storage layer filters by namespace when performing DELETE.

### PH-13: K8s Snapshot GET Path Cross-Org Read
**Hypothesis**: The K8s standard GET path (via storageWrapper.Get at storage_without_create.go:51-57) may allow cross-namespace reads if namespace enforcement is not strict. The storage strips deleteKey and dashboard data, but a user could still see snapshot metadata across orgs.
**Test**: Check if K8s namespace enforcement prevents cross-org reads.

### PH-14: Test Receiver Error Message Contains Webhook URL with Secret
**Hypothesis**: When testing a VictorOps receiver, the URL (typed as `Secret`) is used to make an HTTP call. If the call fails, the error message from the HTTP client (e.g., "dial tcp: lookup attacker.com: no such host") may include the URL, leaking the secret to the test caller.
**Test**: Trace the alerting library's TestReceivers flow to see how errors are constructed.
