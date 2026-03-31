# Bypass Analysis: CVE-2019-19023 — Patch a14a4d246

**Advisory:** CVE-2019-19023 / GHSA-3868-7c5x-4827  
**Severity:** CRITICAL — Privilege escalation / Authorization bypass (CWE-269)  
**Commit:** a14a4d246836d2760d2c9651a9e226270b6265a5  
**Author:** Chlins Zhang  
**Date:** 2024-12-27  
**Cluster ID:** preheat-auth-unification-2024  

---

## Patch Summary

The patch unifies auth-data deserialization into a single `Decode()` method on the `Instance` model (`src/pkg/p2p/preheat/models/provider/instance.go`). Before the patch, the manager's `Get()` method deserialized `AuthData` inline, while `GetByName()` and `List()` returned raw DAO objects with `AuthInfo` unpopulated (nil/empty). Callers downstream would receive an `Instance` with `AuthData` set but `AuthInfo` unset, which is the field actually consumed by provider drivers (`getCred()`) during preheat job execution.

The fix adds a canonical `Decode()` method that calls `decodeAuthData()`, then applies it uniformly in `manager.Get()`, `manager.GetByName()`, and `manager.List()`.

### Pre-patch Vulnerable State (Reconstructed)

| Method | Pre-patch behavior | Post-patch behavior |
|---|---|---|
| `manager.Get()` | Inlined `json.Unmarshal` into `AuthInfo` | Delegates to `ins.Decode()` |
| `manager.GetByName()` | Returned raw DAO result — **AuthInfo was nil** | Delegates to `ins.Decode()` |
| `manager.List()` | Returned raw DAO slice — **AuthInfo was nil for all** | Iterates and calls `ins.Decode()` |

When `AuthInfo` was nil, any code path using `instance.AuthInfo` to construct credentials operated with empty auth data. In non-`NONE` auth modes this could allow unauthenticated requests to the P2P provider backend to succeed if the downstream provider did not enforce its own auth check independently.

---

## Bypass Verdict: `bypassable`

The fix is **incomplete**. One alternate entry point inside the HTTP handler layer (`src/server/v2.0/handler/preheat.go`) performs its own independent raw `json.Unmarshal` on `model.AuthData` instead of using the now-populated `model.AuthInfo` field after `Decode()`.

---

## Evidence

### Finding 1: `convertInstanceToPayload` — Independent Raw Unmarshal (Handler Layer)

**File:** `src/server/v2.0/handler/preheat.go`, lines 521–545

```go
func convertInstanceToPayload(model *instanceModel.Instance) (*models.Instance, error) {
    if model == nil {
        return nil, errors.New("instance can not be nil")
    }

    var authInfo = map[string]string{}
    var err = json.Unmarshal([]byte(model.AuthData), &authInfo)  // <-- raw unmarshal on AuthData
    if err != nil {
        return nil, err
    }
    return &models.Instance{
        AuthInfo:       authInfo,
        ...
    }, nil
}
```

This function is called from:
- `GetInstance` (line 120) — `GET /preheat/instances/{name}`
- `ListInstances` (line 152) — `GET /preheat/instances`
- `ListProvidersUnderProject` (line 841) implicitly (does not call this, reads `AuthInfo` directly)

The `model` passed in is the result of `preheatCtl.GetInstanceByName()` or `preheatCtl.ListInstance()`, which have now been patched to call `Decode()` and populate `model.AuthInfo`. However, `convertInstanceToPayload` **ignores `model.AuthInfo`** and re-unmashals from `model.AuthData` directly. This means:

1. If `model.AuthData` is an empty string (which is the valid default for `AuthModeNone` instances), `json.Unmarshal([]byte(""), &authInfo)` returns `unexpected end of JSON input`, causing the function to return an error rather than returning an empty-auth instance. This is a **denial of service** on listing/getting `NONE`-mode preheat instances.

2. The fix is semantically redundant for this path — `AuthInfo` is already populated by the patched `Decode()` call before `convertInstanceToPayload` is ever reached, but the function re-derives it from `AuthData` independently. Any future scenario where `AuthData` and `AuthInfo` diverge (e.g., a partial update path that sets one but not the other) would result in the HTTP layer serving stale or incorrect auth information.

3. This represents an **alternate entry point** that was not updated with the centralized `Decode()` pattern, confirming the fix is incomplete in scope.

### Finding 2: `convertParamInstanceToModelInstance` — No Decode Call on Inbound Data

**File:** `src/server/v2.0/handler/preheat.go`, lines 547–581

```go
func convertParamInstanceToModelInstance(model *models.Instance) (*instanceModel.Instance, error) {
    ...
    authData, err := json.Marshal(model.AuthInfo)
    ...
    return &instanceModel.Instance{
        AuthData:       string(authData),
        AuthInfo:       model.AuthInfo,   // <-- AuthInfo populated here from API input
        ...
    }, nil
}
```

This function is used for `CreateInstance` and `UpdateInstance`. It directly sets both `AuthData` (from marshaled `AuthInfo`) and `AuthInfo` on the model. The `CreateInstance` path flows to `manager.Save()` → `dao.Create()`, which persists `AuthData` to the DB. `AuthInfo` has `orm:"-"` so it is not persisted.

The `UpdateInstance` path calls `manager.Update()` → `dao.Update()`. `dao.Update()` calls `o.Update(instance, props...)` with an optional column list. If `AuthData` is not explicitly listed in `props`, it may not be written to the DB. The `UpdateInstance` handler in `preheat.go` does not pass any explicit props, meaning the full model is updated. However this code path does not call `Decode()` after the DAO save either, so the in-memory `AuthInfo` that would be used for the immediate `CheckHealth` call in `PingInstances` comes from the API input, not from DB re-read.

### Finding 3: `PingInstances` — CheckHealth Without Decode on Inline Instance

**File:** `src/server/v2.0/handler/preheat.go`, lines 433–468

```go
func (api *preheatAPI) PingInstances(...) middleware.Responder {
    ...
    if params.Instance.ID > 0 {
        // by ID — uses GetInstance which calls Decode()
        instance, err = api.preheatCtl.GetInstance(ctx, params.Instance.ID)
    } else {
        // by endpoint URL — converts directly from params, NO Decode() call
        instance, err = convertParamInstanceToModelInstance(params.Instance)
    }

    err = api.preheatCtl.CheckHealth(ctx, instance)
```

When `ID` is 0, the instance is constructed inline from the request parameters via `convertParamInstanceToModelInstance()`. This path sets `AuthInfo` directly from the API input without any canonical decoding or validation. The `CheckHealth` path then uses this in-memory `AuthInfo` to construct credentials. This is logically safe for a ping (the caller provides their own credentials), but it is an unguarded path where auth data flows without passing through `Decode()`.

### Finding 4: `BasicAuthHandler.Authorize` — Key/Value Confusion

**File:** `src/pkg/p2p/preheat/provider/auth/basic_handler.go`, lines 43–44

```go
key := reflect.ValueOf(cred.Data).MapKeys()[0].String()
req.SetBasicAuth(key, cred.Data[key])
```

`SetBasicAuth(username, password)` is called with the **key** of the first map entry as the username, and the **value** as the password. The `cred.Data` map is `map[string]string` with no schema enforcement. If an attacker can control the JSON keys in `AuthData` (e.g., through a misconfigured update), they could inject arbitrary username values into the `Authorization: Basic` header. Map iteration order in Go is randomized, so when `len(cred.Data) > 1`, the key selected as username is non-deterministic.

This is a pre-existing design flaw not addressed by the patch.

### Finding 5: `CustomAuthHandler.Authorize` — Arbitrary Header Injection

**File:** `src/pkg/p2p/preheat/provider/auth/custom_handler.go`, lines 43–44

```go
key := reflect.ValueOf(cred.Data).MapKeys()[0].String()
req.Header.Set(key, cred.Data[key])
```

The first key in `AuthData` is used as an HTTP header name with no sanitization. An attacker who can create or update a preheat instance with `AuthMode=CUSTOM` and an `AuthData` JSON key that is a sensitive header name (e.g., `Authorization`, `X-Harbor-Csrf-Token`, `Cookie`) can inject arbitrary headers into all outbound HTTP requests made by the preheat driver to the P2P provider endpoint.

The patch does not add any key validation or allowlisting to `decodeAuthData()` or to the `CustomAuthHandler`. The `AuthMode` value is also stored as a plain string with no validation that it matches a known handler.

---

## Alternate Entry Points Summary

| Path | Calls Decode()? | Risk |
|---|---|---|
| `manager.Get()` | Yes (patched) | Fixed |
| `manager.GetByName()` | Yes (patched) | Fixed |
| `manager.List()` | Yes (patched) | Fixed |
| `handler.convertInstanceToPayload()` | No — raw unmarshal on AuthData | Alternate entry point, partial DoS |
| `handler.PingInstances` (inline path) | No | Unguarded |
| `CustomAuthHandler.Authorize` | N/A | Header injection not addressed |
| `BasicAuthHandler.Authorize` | N/A | Key/value confusion not addressed |

---

## LDAP Injection Assessment

No LDAP interaction was found in the preheat auth path. The P2P preheat subsystem uses its own `auth` package (`src/pkg/p2p/preheat/provider/auth/`) which is entirely HTTP-credential based (Basic, OAuth Bearer, Custom Header). Harbor's LDAP auth subsystem (`src/core/auth/ldap/`) is separate and not exercised by this code path.

---

## Type Confusion Between Auth Modes

The `AuthMode` field is a plain string stored in the DB with no foreign-key or allowlist constraint at the model level. The handler enforces nothing on `AuthMode` beyond what the OpenAPI spec may require. If an attacker sets `AuthMode` to an unregistered value, `GetAuthHandler()` returns `ok=false` and the request to the P2P provider proceeds without any auth header being set. This represents a mode confusion bypass: by storing an unknown `AuthMode`, an instance can be made to effectively bypass its own authentication when the health check or preheat job runs.

---

## Recommendations

1. Update `convertInstanceToPayload()` in `preheat.go` to use `model.AuthInfo` directly (already populated by `Decode()`) instead of re-running `json.Unmarshal` on `model.AuthData`. Handle the `AuthData == ""` case explicitly.

2. Add key-name validation or an allowlist in `CustomAuthHandler.Authorize` to prevent arbitrary HTTP header injection from attacker-controlled `AuthData` keys.

3. Validate `AuthMode` against the `knownHandlers` registry at model creation/update time (API handler layer), rather than silently falling back to unauthenticated behavior.

4. Fix the non-deterministic map key selection in `BasicAuthHandler.Authorize` — define and enforce a specific key name (e.g., `"username"`) rather than taking the first arbitrary map key.

