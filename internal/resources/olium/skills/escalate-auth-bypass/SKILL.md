---
name: escalate-auth-bypass
description: Turn a suspected or confirmed authentication/authorization bypass into impact — admin access, session takeover, privilege escalation, or cross-tenant read. Use when you find a missing auth check on a route, a weak JWT verifier, a session cookie that's predictable or reusable across users, a privilege field client-controllable, or an audit finding tagged CWE-287/CWE-863/CWE-639. Walks from probe to admin-equivalent capability and persists a finding with the highest-impact action you reached.
license: MIT
allowed-tools:
  - query_records
  - inspect_record
  - replay_request
  - list_auth_sessions
  - auth_session_lookup
  - attack_kit
  - report_finding
  - update_finding
  - remember
  - update_plan
---

# Auth Bypass → Impact Escalation

You have a suspected auth weakness. Your job is to turn it into the
strongest impact you can demonstrate — admin access, cross-tenant data
read, token forgery, or session takeover — and persist a finding with the
specific action that proves it. Reporting "missing auth check" without
showing what it gets you is not a finding.

## When this skill applies

- A route responds 200 with no `Authorization` / session cookie when it
  should require auth (compare to a known-auth'd record's response).
- JWT verification accepts `alg: none`, a key-confused HMAC secret, or a
  token signed with the public key as HMAC secret.
- A session ID is predictable (sequential, time-based, or short).
- A request body / query has a role/tenant/user field that, when changed,
  changes the response (`role=user` → `role=admin`, `tenant=A` → `tenant=B`).
- Audit harness flagged CWE-287, CWE-862, CWE-863, CWE-639, CWE-284, or
  CWE-639 — even theoretical.

## Workflow

### 1. Establish baselines

Use `list_auth_sessions` to see which auth contexts already exist for the
host. Use `auth_session_lookup` to pull the actual headers for at least
two roles if you have them (`anon` + `user` is enough; `user` + `admin`
is ideal). `remember` the role boundaries as `auth-roles`.

If only one role is available, use `query_records` to find an
unauthenticated record for the same endpoint to anchor the no-auth
baseline.

### 2. Classify the weakness

Pick **one** mechanism to attack — don't shotgun:

- **Missing auth on route**: pick the suspect endpoint, send the request
  with `replay_request` and `extra_headers: {}` to strip cookies. If you
  still get the privileged response, the route doesn't check auth at all.
- **Weak JWT**: decode the token (base64 each segment). Look at `alg`,
  `iss`, `aud`, `exp`, `sub`, custom claims (`role`, `tenant`). Re-mint:
  - `alg: none`: build header `{"alg":"none","typ":"JWT"}`, keep payload,
    drop signature (empty 3rd segment).
  - Key confusion: sign HMAC with the public key as the secret.
  - Empty / weak HMAC secret: try `""`, `secret`, `key`, the app name.
- **Session prediction**: collect 5-10 valid session IDs from `query_records`
  on login responses. If they're sequential, time-encoded, or short
  hex/base64, forge a neighboring ID via `replay_request`.
- **Privilege field client-controlled**: send the request with the role
  field flipped (`role=admin`, `is_admin=true`, `tenant_id=<other>`).

### 3. Confirm escalation, don't stop at "different"

A 200 with different content is *suspicious*, not proof. Confirm with
ONE of:

- The response body contains data the original role couldn't see (admin
  email, another user's email, a hidden flag).
- A privileged action succeeds: `DELETE /api/users/X`, `POST /api/admin/X`,
  `GET /api/users/all` returns a list of more than just the current user.
- A subsequent request using the forged session is accepted as that user
  (look up the user's email or role in the response).

Send the **smallest privileged request that proves the boundary was
crossed**. `remember` it with key `auth-bypass-proof` and include the
exact request line.

### 4. Map the blast radius

Briefly enumerate the surface the bypass unlocks. Don't enumerate at
scale — show:

- 1 admin-only endpoint reachable.
- 1 cross-tenant record visible.
- 1 sensitive write that succeeds (if write paths exist; do **not**
  destructively delete or modify real data — read or create-with-rollback
  if possible).

This sizes the severity in the finding without spamming requests.

### 5. Persist the finding

Call `report_finding`:

- `severity`: `critical` if you reached admin or full cross-tenant; `high`
  for same-tenant privilege escalation or read of another user's data.
- `title`: name the mechanism and the proven action — `"JWT alg=none
  accepted; forged admin token reads /api/admin/users (1234 users)"`.
- `cwe_id`: CWE-287 (auth missing), CWE-863 (broken auth check),
  CWE-639 (IDOR-style), CWE-345 (insufficient verification of data),
  CWE-347 (weak signature) — pick the one that matches the mechanism.
- `description`: 3 sentences. Mechanism, proof, blast radius. Include the
  decoded JWT header / forged session ID / mutated field value in the
  description body so the reproduction is unambiguous.

If the audit harness already raised this, `update_finding` to triaged
status referencing the new proof.

## Pitfalls

- Do not perform destructive writes (`DELETE`, `PUT` overwriting,
  password resets) on someone else's account. Read-only proofs are
  sufficient for severity.
- A forged token that returns 200 with an empty body proves nothing.
  The body must contain data the original role didn't have access to.
- Some apps return 200 with `error: "unauthorized"` in the JSON body —
  read the body, not just the status, before claiming bypass.
- If the app has a "demo admin" account that's publicly accessible by
  design, that's not a bypass — confirm by checking documentation or
  a comment in the code (`--source` mode).
- IDOR (object-level missing auth) is a related but distinct pattern —
  if your finding is "can read another user's order by changing the
  ID", use `idor-blast-radius` instead.

## Output expectations

- One `report_finding` with the strongest proven impact.
- A `remember` note with the canonical bypass request.
- Plan item marked `done`.
