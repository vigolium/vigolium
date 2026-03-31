# Round 1 Hypotheses — core-probe

## PH-01: OAuth2 parameter override via merge order

- **Reasoning-Model**: Pre-Mortem
- **Target**: `kong/plugins/oauth2/access.lua:209-221` — `retrieve_parameters`
- **Attacker starting position**: unauthenticated
- **Attack input**: `POST /oauth2/token?grant_type=authorization_code&client_id=public&code=valid` with body `grant_type=password&authenticated_userid=victim&provision_key=LEAKED_KEY`
- **Chain**: attacker sends conflicting query/body params → `retrieve_parameters` merges with body overriding query → `issue_token` reads body grant_type/password flow → token issued for `authenticated_userid=victim`
- **Catastrophe / Dangerous fallback**: attacker obtains access tokens using a grant type the upstream gatekeeper would have rejected.
- **Severity estimate**: HIGH
- **Read needed**: `kong/plugins/oauth2/access.lua:209-221`
- **Deepening direction**: identify any upstream components that validate only query parameters or rely on query-first semantics.

---

## PH-02: Password grant impersonation with leaked provision key

- **Reasoning-Model**: Pre-Mortem
- **Target**: `kong/plugins/oauth2/access.lua:737-764` — `issue_token` (password grant)
- **Attacker starting position**: unauthenticated
- **Attack input**: `POST /oauth2/token` body `grant_type=password&client_id=app&client_secret=secret&provision_key=LEAKED_KEY&authenticated_userid=admin`
- **Chain**: attacker supplies provision_key + arbitrary authenticated_userid → password grant path only validates provision_key and presence of authenticated_userid → `generate_token` issues token for `admin`
- **Catastrophe / Dangerous fallback**: full impersonation of any user if provision_key is exposed.
- **Severity estimate**: CRITICAL
- **Read needed**: `kong/plugins/oauth2/access.lua:737-764`
- **Deepening direction**: verify how provision_key is distributed/rotated and whether any other checks bind authenticated_userid to an upstream identity.

---

## PH-03: Cross-service refresh token reuse when global credentials enabled

- **Reasoning-Model**: Pre-Mortem
- **Target**: `kong/plugins/oauth2/access.lua:767-809` — `issue_token` (refresh token)
- **Attacker starting position**: authenticated-user (stolen refresh token)
- **Attack input**: `POST /service-b/oauth2/token` body `grant_type=refresh_token&refresh_token=STOLEN_FROM_SERVICE_A&client_id=app&client_secret=secret`
- **Chain**: attacker uses refresh token from Service A → service_id check skipped when `conf.global_credentials` is true → `generate_token` issues token bound to current route’s service → access shifts to Service B
- **Catastrophe / Dangerous fallback**: lateral movement across services using a single stolen refresh token.
- **Severity estimate**: HIGH
- **Read needed**: `kong/plugins/oauth2/access.lua:767-809`
- **Deepening direction**: confirm whether `global_credentials` is enabled and whether refresh tokens are expected to be service-scoped in deployment.

---

## PH-04: Non-expiring JWT accepted when exp not enforced

- **Reasoning-Model**: Pre-Mortem
- **Target**: `kong/plugins/jwt/handler.lua:238-249` — `do_authentication` (claims + max expiration)
- **Attacker starting position**: authenticated-user (stolen JWT secret)
- **Attack input**: `Authorization: Bearer <JWT with no exp claim, signed with leaked secret, kid=cred123>`
- **Chain**: attacker crafts JWT without exp → `verify_registered_claims(conf.claims_to_verify)` succeeds if exp not configured → `check_maximum_expiration` skipped when unset → token accepted indefinitely
- **Catastrophe / Dangerous fallback**: persistent access even after intended token lifetimes.
- **Severity estimate**: HIGH
- **Read needed**: `kong/plugins/jwt/handler.lua:238-249`
- **Deepening direction**: inspect configuration defaults for `claims_to_verify` and `maximum_expiration` across deployments.

---

## PH-05: HS256 verification using public key as HMAC secret

- **Reasoning-Model**: Pre-Mortem
- **Target**: `kong/plugins/jwt/handler.lua:209-236` — `do_authentication` (algorithm + secret selection)
- **Attacker starting position**: unauthenticated
- **Attack input**: `Authorization: Bearer <JWT alg=HS256, kid=cred123, signed using RSA public key as HMAC secret>`
- **Chain**: attacker forges token using publicly-known RSA key → credential stored with `algorithm=HS256` and `secret` incorrectly set to RSA public key → plugin uses `jwt_secret.secret` as HMAC key → signature verification passes
- **Catastrophe / Dangerous fallback**: any actor with public key can mint valid JWTs for that consumer.
- **Severity estimate**: HIGH
- **Read needed**: `kong/plugins/jwt/handler.lua:209-236`
- **Deepening direction**: confirm whether credential provisioning can misassign RSA public keys into `secret` with HS algorithms.

---

## PH-06: Cluster RPC WebSocket node_id impersonation with stolen cert

- **Reasoning-Model**: Pre-Mortem
- **Target**: `kong/clustering/rpc/manager.lua:507-549` — `handle_websocket`
- **Attacker starting position**: network-adjacent (stolen DP client cert)
- **Attack input**: WebSocket upgrade to `/v2/outlet` with `Sec-WebSocket-Protocol: kong.meta.v1`, valid client cert, and meta handshake frame claiming `node_id=control_plane`
- **Chain**: attacker establishes RPC websocket with valid cert → server accepts protocol and validates cert only → `_handle_meta_call` accepts attacker-supplied node_id → socket registered as privileged node → attacker can invoke RPC methods as that node
- **Catastrophe / Dangerous fallback**: unauthorized cluster control actions or config poisoning.
- **Severity estimate**: CRITICAL
- **Read needed**: `kong/clustering/rpc/manager.lua:507-549`
- **Deepening direction**: check if `_handle_meta_call` binds node_id to cert identity or allows arbitrary node_id claims.

---

## PH-07: Router flavor change enables route mismatch bypass

- **Reasoning-Model**: Pre-Mortem
- **Target**: `kong/router/init.lua:40-64` — `new` (router flavor selection)
- **Attacker starting position**: authenticated-admin (control-plane config access)
- **Attack input**: configuration change `router_flavor=traditional_compatible` followed by request `GET /%2e%2e/admin` against a path-sensitive route
- **Chain**: attacker changes router flavor → runtime loads different router implementation → route matching/normalization differs → crafted URI matches a less-protected route → auth plugin chain not applied as expected
- **Catastrophe / Dangerous fallback**: access to routes that should be protected under the default router flavor.
- **Severity estimate**: HIGH
- **Read needed**: `kong/router/init.lua:40-64`
- **Deepening direction**: compare normalization/matching behavior across router flavors for ambiguous paths/hosts.

---

## Coverage Check

| Entry Point | Pre-Mortem covered? | Abductive covered? |
|------------|:-:|:-:|
| `kong/runloop/handler.lua:1211-1225` — router exec | NO — out of scope per user request | NO — out of scope per user request |
| `kong/router/traditional.lua:1755-1788` — traditional exec | NO — out of scope per user request | NO — out of scope per user request |
| `kong/router/atc.lua:443-507` — expressions exec | NO — out of scope per user request | NO — out of scope per user request |
| `kong/router/utils.lua:57-64` — `strip_uri_args` | NO — out of scope per user request | NO — out of scope per user request |
| `kong/runloop/handler.lua:1357-1365` — WebSocket upgrade | NO — out of scope per user request | NO — out of scope per user request |
| `kong/clustering/control_plane.lua:191-236` — CP websocket | NO — out of scope per user request | NO — out of scope per user request |
| `kong/clustering/data_plane.lua:200-257` — DP websocket | NO — out of scope per user request | NO — out of scope per user request |
| `kong/clustering/rpc/manager.lua:507-562` — RPC websocket | PH-06 | NO |
| `kong/runloop/plugin_servers/rpc/mp_rpc.lua:172-218` — MsgPack RPC | NO — out of scope per user request | NO — out of scope per user request |
| `kong/runloop/plugin_servers/rpc/pb_rpc.lua:268-328` — ProtoBuf RPC | NO — out of scope per user request | NO — out of scope per user request |
| `kong/plugins/jwt/handler.lua:154-250` — JWT do_authentication | PH-04/PH-05 | NO |
| `kong/plugins/oauth2/access.lua:209-221` — retrieve_parameters | PH-01 | NO |
| `kong/plugins/oauth2/access.lua:533-812` — issue_token | PH-02/PH-03 | NO |
| `kong/resty/dns/client.lua:742-883` — DNS resolver | NO — out of scope per user request | NO — out of scope per user request |
| `kong/templates/nginx_kong.lua:97-519` — HTTP/2 config | NO — out of scope per user request | NO — out of scope per user request |

| Defensive Pattern | Abductive hypothesis generated? |
|------------------|:-:|
| (none listed in anatomy) | NO — not applicable: Code Anatomy has no Defensive Patterns section |

| Trust Chain Gap | Backward chain traced? |
|----------------|:-:|
| Router normalization consistency vs HTTP/2 entry | NO — out of scope per user request |
| AuthZ decision finality influenced by external plugin RPC | NO — out of scope per user request |
| External plugin RPC framing lacks explicit size limits | NO — out of scope per user request |
| CP/DP sync legacy path validations | NO — out of scope per user request |
| DNS resolver safety depends on OpenResty version | NO — out of scope per user request |
| HTTP/2 limit enforcement depends on core | NO — out of scope per user request |
