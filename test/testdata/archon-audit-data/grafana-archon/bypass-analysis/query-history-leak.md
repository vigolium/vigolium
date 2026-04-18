# Bypass Analysis: Query History Cross-User Data Leak

- **Commit**: dc9ac13e84a1d023e2e1395fad294f401b6bcfb4
- **Component**: Query history service (`pkg/registry/apps/queryhistory/register.go`, storage authorizer, search handler)
- **Tag**: [undisclosed]
- **Cluster ID**: query-history-authz

## Patch Summary

The patch addresses three distinct authorization gaps in the query history service:

1. **Fail-open on transient storage errors**: The pre-patch authorizer allowed all authenticated users unrestricted CRUD on all query history items (`case "get", "list", "watch", "create", "update", "patch", "delete", "deletecollection": return DecisionAllow`). The post-patch authorizer performs ownership checks for `get/update/patch/delete` by reading the resource from unified storage and comparing the `created-by` label. On transient storage errors, the new code returns `DecisionDeny` instead of failing open.

2. **Mode5 list/get namespace filtering**: A new `NamespaceScopedStorageAuthorizerProvider` was added (`queryHistoryStorageAuthorizer`) that wraps the k8s storage layer. It provides `AfterGet()` and `FilterList()` hooks to enforce that only the requesting user's items are returned in Mode5 (unified storage).

3. **Search endpoint filtering**: The search handler now includes a hard-coded `created_by = userUID` field requirement, ensuring the search index only returns items belonging to the requesting user. The `Queries` field was removed from search results (reducing data exposure surface).

Additional hardening: Legacy storage `Get()` was rewritten to use a new `GetQueryByUID()` method with `WHERE org_id = ? AND created_by = ? AND uid = ?` instead of fetching all 1000 items and filtering client-side.

## Bypass Verdict: **bypassable** (residual risks, not full bypass)

## Evidence

### 1. Watch verb bypasses ownership filtering (MEDIUM)

The `Wrapper.Watch()` method in `storewrapper/wrapper.go` (line 225-229) passes through to the inner store **without any filtering**. The `queryHistoryStorageAuthorizer` has no `FilterWatch` hook, and the `ResourceStorageAuthorizer` interface does not define one. The API-level authorizer allows `watch` unconditionally (grouped with `list`, `create`, `deletecollection` -- all allowed without ownership check).

A user who issues a `watch` request on the query history resource will receive change events for **all users' items** in the namespace, because:
- The API-level authorizer allows `watch` for any authenticated user.
- The storage wrapper's `Watch()` does not call `FilterList` or any equivalent.
- The `queryHistoryStorageAuthorizer` has no watch-filtering hook.

**Impact**: Cross-user data leak via watch events in Mode5. An attacker can open a watch stream and observe all query history create/update/delete events across users.

**File**: `pkg/services/apiserver/auth/authorizer/storewrapper/wrapper.go:225-229`

### 2. Missing `created-by` label allows ownership bypass (LOW-MEDIUM)

Both the API-level authorizer and the storage-level authorizer fail open when `createdBy` is empty:

- `checkOwnership()` (register.go): `if err != nil || createdBy == "" { return authorizer.DecisionAllow, "", nil }`
- `AfterGet()`: `if createdBy != "" && createdBy != user.GetIdentifier() { ... }` -- empty label passes through.
- `FilterList()`: `if createdBy := ...; createdBy == "" || createdBy == userID { filtered = append(...) }` -- empty label is included.

If a query history item exists without a `created-by` label (e.g., from a migration gap, direct DB manipulation, or a bug in the mutator), any authenticated user can access it. The validator enforces label immutability on updates, but does not enforce label presence on creation (that is delegated to the mutator, which is a separate component).

### 3. `deletecollection` allowed without ownership check (LOW)

The API-level authorizer allows `deletecollection` for any authenticated user without ownership verification. The storage wrapper's `DeleteCollection()` returns `errors.NewMethodNotSupported(...)`, which provides protection -- but only when the `NamespaceScopedStorageAuthorizerProvider` wraps the store. In legacy storage mode or if the wrapper is not applied, this could allow a user to delete other users' items.

### 4. `storageClient == nil` fallback allows bypass in mixed modes (LOW)

The `checkOwnership()` method falls back to `DecisionAllow` when `storageClient` is nil. The comment states this is for "Mode0 with legacy-only storage" where SQL WHERE clauses handle isolation. However, if the storage client is nil for other reasons (misconfiguration, initialization race), this becomes a fail-open path.

### 5. `resp.Error != nil` allows probing (INFORMATIONAL)

When `checkOwnership()` gets a storage response error (e.g., resource not found), it returns `DecisionAllow` to let the handler return a proper 404. This is correct behavior, but it means the authorizer does not distinguish between "resource does not exist" and "storage reports an error code." A malformed storage error response could bypass ownership checks.

### 6. Search endpoint relies on index-level filtering only (LOW)

The search handler filters by `created_by = userUID` at the search index level. This is correct, but it does not go through the storage-level authorizer. If the search index is stale, inconsistent, or has a bug in the `created_by` field indexing, results from other users could leak. This is a defense-in-depth concern rather than a direct bypass.

## Related Patterns

The `live` and `annotation` app registrations (`pkg/registry/apps/live/register.go`, `pkg/registry/apps/annotation/authz.go`) both use broad `DecisionAllow` authorizers for all authenticated users. These are mentioned for completeness -- they may have similar isolation requirements but handle authorization differently (annotations use per-operation checks in the REST adapter).

## Recommendations

1. **Critical**: Add watch-level filtering or deny `watch` in the authorizer until `ResourceStorageAuthorizer` supports a `FilterWatch` hook.
2. **Medium**: Change empty `createdBy` handling from allow to deny in both the API-level and storage-level authorizers. Items without ownership labels should be inaccessible to regular users.
3. **Low**: Audit the mutator to confirm it always sets the `created-by` label on creation. Add a validation admission check that rejects creates without the label.
4. **Low**: Consider denying `deletecollection` at the API-level authorizer explicitly, rather than relying on the storage wrapper to block it.
