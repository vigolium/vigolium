---
name: idor-blast-radius
description: When you find an Insecure Direct Object Reference (a URL/body/header parameter that lets you read or write another user's or another tenant's object), discover the ID space, prove the access is unauthorized, quantify the blast radius (how many records reachable, what data class, read vs write, same-tenant vs cross-tenant), and persist a finding sized by real impact rather than by the existence of the flaw. Use when an ID parameter (numeric, UUID, hash, slug, or an indirect ref in a header/cookie) changes the response across IDs, when CWE-639/CWE-284/BOLA was flagged, or when an audit finding hints at object-level access control gaps.
license: MIT
tags:
  - idor
  - bola
  - access-control
allowed-tools:
  - query_records
  - inspect_record
  - replay_request
  - report_finding
  - update_finding
  - remember
  - update_plan
---

# IDOR → Blast-Radius Sizing

You have an IDOR candidate: an endpoint where flipping an object reference
returns or mutates an object you don't own. Your job is to find the ID
space, prove the access is unauthorized, size the impact (how many objects,
what data class, read vs write, same-tenant vs cross-tenant), and persist a
finding that reflects real severity — not theoretical.

## When this skill applies

- A path/query/body param looks like `/users/{id}`, `/orders/{id}`,
  `/files/{uuid}`, `/exports/{slug}` — and changing the ref changes the
  response in a way the auth context shouldn't allow.
- The reference is *indirect*: an account id in a JWT claim, a `X-Account-Id`
  header, a tenant id in a cookie, a hidden form field. These are IDOR too.
- Two different sessions return the same object for the same ID — the server
  doesn't filter by `current_user` / `current_tenant`.
- CWE-639 / CWE-284 / "BOLA" / "Broken Object Level Authorization" / "mass
  assignment of owner field" in an audit finding.

Don't run this on endpoints that are intentionally cross-user public
(`/users/{id}/avatar` is sometimes public; check before claiming).

## Workflow

### 1. Establish two identities and a baseline

You need a second reference point to prove "this is someone else's object",
not just "this object exists". In order of preference:

1. A second authenticated session (`query_records` / prior auth) — best.
2. An object id you legitimately own + a neighboring id you don't.
3. Unauthenticated replay of an authenticated endpoint (if it returns data
   without a session, that's a stronger, separate finding — note it).

`replay_request` your own id + your own session → record the canonical
"authorized" response (status, length, a unique field like your email).

### 2. Discover the ID space (don't assume it's enumerable)

Collect every id you've seen for this handler from `query_records`, then
classify and find a *source of valid ids* before probing:

- **Sequential numeric** (`1, 2, 3, 5, 6…`): full enumeration trivial.
- **Sequential with gaps** (`1004, 1009, 1011…`): probe a range; gaps are
  deletes, not auth.
- **Timestamped / snowflake** (`1700000000123…`, Twitter-style ids): the
  high bits are a clock — neighbors are ids created near yours in time.
- **UUID v1** (`xxxxxxxx-xxxx-1xxx-…`): time + MAC encoded — *not* random.
  Ids minted close in time share a prefix; partially predictable.
- **UUID v4** (`…-4xxx-[89ab]xxx-…`): not enumerable from outside — you
  need a leak. Hunt list endpoints, comment threads, `Referer`/`Location`
  headers, search results, error messages, sitemaps, JS bundles.
- **Hashids / short hash** (`a3f9`, `7c2k`, `gY3p`): often a reversible
  encoding of a sequential int (hashids, sqids, base62). Decode a few of
  *your own* ids; if they map to small consecutive integers, it's
  sequential in disguise — enumerable.
- **Slug** (`order-john-2024-001`): semi-predictable; try permutations of
  the variable parts you can infer.

`remember` the format + the id source as `idor-id-space`. If the space is
UUIDv4 and you found no leak, say so in the finding — "enumerable only with
a valid id source" caps the realistic blast radius.

### 3. Confirm the access is unauthorized

`replay_request` a neighboring / other-owner id with **your** session:

- Different object's data (different email, owner, content) → IDOR confirmed.
- `403` / `404` / `{error:"not found"}` body → the auth check works. Read the
  **body**, not just the status; some apps 200 with an error envelope.
- Same object regardless of id → not an object ref; move on.

Re-confirm once (a second neighboring id) so a single coincidental match
doesn't drive a finding.

### 4. Size — sample, don't crawl

Probe **20–50 ids maximum** chosen to cover the space, never the whole range:

- ~10 near yours (`your_id ± 5`), ~10 near the low end, ~10 near an
  estimated high end.
- For hashids, decode→increment→re-encode to generate neighbors.

Count, per status, how many returned another principal's data. Project the
total ("28/30 sampled ids resolved; ids run 1–~50000 → ~all 50k users
reachable") and state the *projection* in the finding, not 50000 requests.

`remember` the count as `idor-reachable`.

### 5. Determine data class

For 1–3 leaked records, note what's exposed and categorize:

- **Credentials** (password hash, API key, session/refresh token) — critical.
- **Financial** (balance, payment method, transaction history) — critical.
- **PII** (email, name, address, phone, DOB, gov id) — high (minimum).
- **Content** (private messages, files, drafts) — high.
- **Metadata only** (created_at, opaque ids) — medium.

### 6. Check the write path

Try `PUT` / `POST` / `PATCH` / `DELETE` with the other-owner id and the body
the legitimate owner would send. **Do not destructively modify or actually
elevate.** A `200`/`204` (or a reflected-back changed field) proves the write
path — note it, then stop. Probe owner/role fields specifically
(`{"role":"admin"}`, `{"owner_id":<you>}`) for mass-assignment-style
privilege takeover; confirm via a read-back, do not leave the change in place.

Read-IDOR is high; write-IDOR is critical.

### 7. Check the tenant boundary

If the app is multi-tenant, repeat step 3 with an id from a *different
tenant/org*, not just a different user in your tenant. Cross-tenant read or
write is the worst flavor — it breaks the product's core isolation promise.
Flag it explicitly: same-tenant vs cross-tenant changes both severity and
the disclosure urgency.

### 8. Persist the finding

`report_finding` once per IDOR pattern (not per id probed):

- `severity`: (data class) × (read|write) × (same|cross-tenant) — use the
  tables above; cross-tenant write of credentials/financial is "contact the
  customer ASAP" critical.
- `title`: endpoint + ref type + blast + tenancy, e.g. `"IDOR on GET
  /api/orders/{id} reads all ~12k orders cross-tenant; sequential numeric id"`.
- `cwe_id`: CWE-639.
- `description`: 3–4 sentences — endpoint, ref type + id source, ids probed,
  count reached, data class, read/write, same vs cross-tenant.
- Include 1 **masked** sample row from another principal (`***@***`).

If the audit harness already filed a theoretical finding for the same
endpoint, `update_finding` with `status: triaged` and the new evidence
instead of double-reporting.

## Pitfalls

- Don't paste 50 real emails/records into the finding. One masked sample +
  the count + projection is what matters.
- A 200 with empty body, or a 200 `{error:"not found"}`, is not a leak —
  read the body before claiming.
- "I got data" + "I'm an admin in this app" = not IDOR; you're allowed to
  see it. Confirm your session is a regular, low-privilege role.
- UUIDv4 with no id source is *not* "all users reachable" — cap the claim.
- Hashids/short slugs that look opaque are frequently sequential ints in
  disguise; decode before declaring the space non-enumerable.
- A neighbor id returning data could be *your own* second object. Verify the
  owner field differs from your principal.

## Output expectations

- One finding per IDOR pattern (not per id probed).
- A `remember` note with the canonical proof request, id source, and
  projection.
- Plan item marked `done`.
