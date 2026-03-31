# Evidence — core-probe

## [HARVESTER] PH-01 (R1): OAuth2 parameter override via merge order

**Verdict**: VALIDATED

**Code path**:
1. `kong/plugins/oauth2/access.lua:209-218` — `retrieve_parameters()` merges query/body (`kong.table.merge(uri_args, body_args)`) for POST/PUT/PATCH.
2. `kong/pdk/table.lua:41-53` → `kong.tools.table.table_merge` — merge behavior: keys from second table override first.
3. `kong/tools/table.lua:32-44` — `table_merge` copies t1 then t2, so body overwrites query on key collisions.
4. `kong/plugins/oauth2/access.lua:533-760` — `issue_token()` reads `parameters[grant_type]`, `parameters[authenticated_userid]`, etc. from merged table.

**Sanitizers on path**:
- `kong/plugins/oauth2/access.lua:549-760` — `issue_token` grant-type and provision-key checks — **Partial**: validates values but does not prevent query/body source confusion.

**Verdict rationale**: For POST requests, `retrieve_parameters()` explicitly merges query and body with body values overriding. All later token issuance logic consumes the merged table, so conflicting query/body inputs can steer grant type, client_id, or authenticated_userid selection.

---

## [HARVESTER] PH-02 (R1): Password grant impersonation with leaked provision key

**Verdict**: VALIDATED

**Code path**:
1. `kong/plugins/oauth2/access.lua:533-538` — `issue_token()` obtains `parameters` via `retrieve_parameters()`.
2. `kong/plugins/oauth2/access.lua:737-763` — password grant branch checks `conf.provision_key` and non-empty `authenticated_userid` then calls `generate_token(...)` with provided `authenticated_userid`.
3. `kong/plugins/oauth2/access.lua:760-763` — sink: `generate_token(..., parameters.authenticated_userid, ...)`.

**Sanitizers on path**:
- `kong/plugins/oauth2/access.lua:739-743` — provision key equality check — **Bypassable**: satisfied if the provision key is leaked as assumed in the hypothesis.
- `kong/plugins/oauth2/access.lua:745-749` — authenticated_userid non-empty check — **Bypassable**: only checks presence, not binding to upstream identity.

**Verdict rationale**: The password grant path only verifies provision_key and that authenticated_userid is present, then issues a token for that user id without additional binding. With a leaked provision key, an attacker can request a token for an arbitrary authenticated_userid.

---

## [HARVESTER] PH-03 (R1): Cross-service refresh token reuse when global credentials enabled

**Verdict**: VALIDATED

**Code path**:
1. `kong/plugins/oauth2/access.lua:533-538` — `issue_token()` obtains merged parameters.
2. `kong/plugins/oauth2/access.lua:767-776` — refresh grant reads `refresh_token` and looks up token.
3. `kong/plugins/oauth2/access.lua:770-773` — `service_id` check only applied when `conf.global_credentials` is **false**.
4. `kong/plugins/oauth2/access.lua:778-789` — rejects when `token` missing or `token.credential.id ~= client.id`.
5. `kong/plugins/oauth2/access.lua:805-809` — sink: `generate_token(conf, kong.router.get_service(), client, token.authenticated_userid, ...)` issues a token bound to the **current** service.

**Sanitizers on path**:
- `kong/plugins/oauth2/access.lua:770-773` — service scoping check — **Partial**: skipped entirely when `conf.global_credentials` is true.
- `kong/plugins/oauth2/access.lua:784-789` — client binding check — **Blocks** cross-client reuse only, not cross-service reuse with same client.

**Verdict rationale**: When `global_credentials` is enabled, the service_id scoping check is skipped. A refresh token tied to client A can be used against a different service (same client) and `generate_token` binds the new access token to the current service.

---

## [HARVESTER] PH-04 (R1): Non-expiring JWT accepted when exp not enforced

**Verdict**: VALIDATED

**Code path**:
1. `kong/plugins/jwt/handler.lua:181-236` — token decoded and signature verified.
2. `kong/plugins/jwt/handler.lua:238-242` — `jwt:verify_registered_claims(conf.claims_to_verify)` only enforces claims listed in config.
3. `kong/plugins/jwt/handler.lua:245-249` — `check_maximum_expiration` runs only if `conf.maximum_expiration > 0`.
4. `kong/plugins/jwt/schema.lua:26-39` — `claims_to_verify` has no default; `maximum_expiration` default is `0` (no max).

**Sanitizers on path**:
- `kong/plugins/jwt/handler.lua:238-242` — registered-claims verification — **Partial**: exp only enforced if included in `claims_to_verify`.
- `kong/plugins/jwt/handler.lua:245-249` — maximum expiration check — **Bypassable** when `maximum_expiration` is 0 (default).

**Verdict rationale**: JWT expiration is only enforced if configured (claims_to_verify includes `exp` or maximum_expiration > 0). With defaults, a token without `exp` is accepted after signature verification.

---

## [HARVESTER] PH-05 (R1): HS256 verification using public key as HMAC secret

**Verdict**: VALIDATED

**Code path**:
1. `kong/plugins/jwt/handler.lua:198-205` — loads credential by key claim.
2. `kong/plugins/jwt/handler.lua:209-227` — selects algorithm and secret: HS* uses `jwt_secret.secret` as HMAC key; non-HS uses `jwt_secret.rsa_public_key`.
3. `kong/plugins/jwt/handler.lua:233-236` — sink: `jwt:verify_signature(jwt_secret_value)` uses chosen secret.

**Sanitizers on path**:
- `kong/plugins/jwt/handler.lua:211-214` — algorithm equality check — **Partial**: ensures alg matches credential but does not validate secret type/entropy.

**Verdict rationale**: For HS algorithms, the plugin uses `jwt_secret.secret` as the HMAC key with no validation of key type. If a credential is misconfigured to store an RSA public key as the HS secret, tokens forged with that public key will verify.

---

## [HARVESTER] PH-06 (R1): Cluster RPC WebSocket node_id impersonation with stolen cert

**Verdict**: VALIDATED

**Code path**:
1. `kong/clustering/rpc/manager.lua:507-531` — `handle_websocket()` validates client cert via `validate_client_cert`.
2. `kong/clustering/rpc/manager.lua:542-545` — `_handle_meta_call(wb, cert)` invoked after cert validation.
3. `kong/clustering/rpc/manager.lua:230-247` — `_handle_meta_call` reads `info.kong_node_id` from client-supplied payload without binding to cert identity.
4. `kong/clustering/rpc/manager.lua:291-335` — `node_id = info.kong_node_id` used to register client capabilities and info.

**Sanitizers on path**:
- `kong/clustering/rpc/manager.lua:527-531` — client certificate validation — **Bypassable** given hypothesis assumes a stolen valid cert.

**Verdict rationale**: Once a valid client cert is accepted, `_handle_meta_call` trusts the `kong_node_id` in the client’s hello payload and registers it, with no binding between node_id and certificate identity.

---

## [HARVESTER] PH-07 (R1): Router flavor change enables route mismatch bypass

**Verdict**: NEEDS-DEEPER

**Code path**:
1. `kong/router/init.lua:40-64` — `new()` selects router module based on `kong.configuration.router_flavor` and returns `router.new(...)` (passes `old_router` for non-traditional flavors).

**Sanitizers on path**:
- None observed in `kong/router/init.lua`.

**Verdict rationale**: `new()` only selects router implementation and forwards parameters. This file alone does not show route matching/normalization differences or cache key reuse behavior that could cause bypasses.

**Deepening note**: Inspect `kong.router.compat` and `kong.router.expressions` constructors for cache reuse and normalization logic, and compare against `traditional` to determine any mismatch window during reload.

---

## [HARVESTER] PH-01 (R2): OAuth2 parameter source confusion via merge order

**Verdict**: VALIDATED

**Code path**:
1. `kong/plugins/oauth2/access.lua:209-218` — `retrieve_parameters()` merges query/body for POST/PUT/PATCH.
2. `kong/tools/table.lua:32-44` — `table_merge` copies t1 then t2, so body overrides query on key collisions.
3. `kong/plugins/oauth2/access.lua:533-706` — `issue_token()` reads `grant_type`, `client_id`, `redirect_uri`, `authenticated_userid`, etc. from merged parameters.

**Sanitizers on path**:
- `kong/plugins/oauth2/access.lua:549-760` — grant-type and client checks — **Partial**: validate values but not the parameter source; body values still override query.

**Verdict rationale**: The merge order ensures body parameters override query values, enabling source confusion when different layers validate only one source.

---

## [HARVESTER] PH-02 (R2): OAuth2 token issuance errors act as client/token oracle

**Verdict**: VALIDATED

**Code path**:
1. `kong/plugins/oauth2/access.lua:561-586` — missing/invalid client triggers `{error="invalid_client"}`.
2. `kong/plugins/oauth2/access.lua:648-659` — invalid authorization code or client mismatch uses `{error="invalid_request"}`.
3. `kong/plugins/oauth2/access.lua:665-668` — PKCE verifier failure propagates error from `validate_pkce_verifier` (e.g., invalid_grant).
4. `kong/plugins/oauth2/access.lua:824-833` — response exits with `response_params` and status 400/401 depending on invalid_client_properties.

**Sanitizers on path**:
- None observed; distinct error strings are returned in JSON response bodies.

**Verdict rationale**: `issue_token()` returns different error codes/messages for client-not-found, code mismatch, and PKCE failures, enabling response-based enumeration.

---

## [HARVESTER] PH-03 (R2): JWT key-claim existence oracle via error differentiation

**Verdict**: VALIDATED

**Code path**:
1. `kong/plugins/jwt/handler.lua:190-206` — missing key claim triggers “No mandatory …”, unknown key triggers “No credentials found for given …”.
2. `kong/plugins/jwt/handler.lua:211-236` — valid key progresses to algorithm and signature checks (“Invalid algorithm” / “Invalid signature”).
3. `kong/plugins/jwt/handler.lua:312-316` — `logical_AND_authentication` returns `err.message` to client when auth fails.

**Sanitizers on path**:
- None observed; error messages differ by failure point and are returned to the client.

**Verdict rationale**: The plugin emits distinct failure messages depending on whether the key claim maps to a credential and whether signature/algorithm validation failed, enabling a key existence oracle.

---

## [HARVESTER] PH-04 (R2): Cluster RPC handshake CPU drain via cert validation on repeated failures

**Verdict**: VALIDATED

**Code path**:
1. `kong/clustering/rpc/manager.lua:507-531` — `handle_websocket()` validates client cert on each connection via `validate_client_cert` before closing.
2. `kong/clustering/rpc/manager.lua:528-531` — invalid cert leads to log + `ngx_exit(HTTP_CLOSE)` after validation work.

**Sanitizers on path**:
- `kong/clustering/rpc/manager.lua:527-531` — certificate validation — **Partial**: rejects invalid certs but still incurs validation cost per attempt; no in-code prefilter/rate limiting.

**Verdict rationale**: Each WebSocket attempt performs cert validation before rejection. The code path has no in-process rate limiting or cheap pre-check, enabling repeated costly failures.

---

## [HARVESTER] PH-05 (R2): Router flavor transition cache mismatch during reload

**Verdict**: NEEDS-DEEPER

**Code path**:
1. `kong/router/init.lua:40-64` — `new()` selects router module by flavor and passes `old_router` for non-traditional flavors.

**Sanitizers on path**:
- None observed in `kong/router/init.lua`.

**Verdict rationale**: The init module shows flavor selection and optional reuse of `old_router` but does not expose cache semantics or route matching behavior needed to confirm mismatch windows.

**Deepening note**: Inspect router flavor constructors for cache key reuse and matching normalization across flavors during reload.

---
