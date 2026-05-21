---
name: idor-blast-radius
description: When you find an Insecure Direct Object Reference (a URL/body parameter that lets you read or write another user's object), quantify the blast radius — how many records reachable, what data class, whether write is also unauthorized — and persist a finding sized by real impact rather than by the existence of the flaw. Use when an ID parameter (numeric, UUID, hash, slug) changes the response content across IDs, when CWE-639/CWE-284 was flagged, or when an audit finding hints at object-level access control gaps.
license: MIT
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

You have an IDOR candidate: an endpoint where flipping an ID parameter
returns a different object than the one you own. Your job is to size the
impact (how many objects reachable, what data class, read vs write) and
persist a finding that reflects real severity, not theoretical.

## When this skill applies

- A URL path or query param looks like `/users/{id}`, `/orders/{id}`,
  `/files/{uuid}`, `/exports/{slug}` — and changing the ID changes the
  response in a way the auth context shouldn't allow.
- Two different sessions return the same object when the ID matches —
  i.e., the server doesn't filter by `current_user`.
- CWE-639 / CWE-284 / "BOLA" / "Broken Object Level Authorization" in an
  audit finding.

Don't run this on endpoints that are intentionally cross-user public
(`/users/{id}/profile` is sometimes public; check before claiming).

## Workflow

### 1. Confirm the IDOR is unauthorized

Two probes via `replay_request` on the suspect record:

1. Replay with your own ID + your own session → baseline.
2. Replay with a neighboring ID (your_id ± 1, or another known ID from
   `query_records`) + your own session → if the response is a different
   object's data (different email, different content), the IDOR exists.

If the second probe returns 403/404, the auth check works; this isn't
IDOR. Move on.

### 2. Classify the ID space

Look at the IDs you've seen across `query_records` for this endpoint:

- **Sequential numeric** (`1, 2, 3, 5, 6...`): full enumeration trivial.
- **Sequential numeric with gaps** (`1004, 1009, 1011...`): still
  trivial, just probe a range.
- **UUID v4** (`a1b2c3d4-...`): not enumerable from outside — need a
  source of IDs. Check if any endpoint leaks them (a list endpoint, a
  comment thread, a referer header).
- **Short hash** (`a3f9`, `7c2k`): probably enumerable; collisions are
  the harder constraint than auth.
- **Slug** (`order-john-2024-001`): semi-predictable; try permutations.

`remember` the ID format as `idor-id-space`.

### 3. Size — don't enumerate all

Sample, don't crawl. Probe **20-50 IDs maximum** chosen to cover the
space:

- 10 IDs near yours (your_id ± 5).
- 10 IDs near the low end (1-10 if numeric).
- 10 IDs near a high end you can estimate.

Count, per response code, how many returned someone else's data. Project
the total: if 28/30 sampled IDs returned a valid record, and IDs run
1-50000, the blast radius is "all 50k users". State the projection in
the finding, not a literal 50000 requests.

`remember` the count as `idor-reachable`.

### 4. Determine data class

For 1-3 of the leaked records, note what data is exposed. Categorize:

- **PII** (email, name, address, phone, DOB) — minimum severity high.
- **Credentials** (password hash, API key, session token) — critical.
- **Financial** (account balance, payment method, transaction history) — critical.
- **Content** (private messages, files, drafts) — high.
- **Metadata only** (created_at, IDs) — medium.

### 5. Check the write path

Try `PUT` / `POST` / `PATCH` / `DELETE` with the same other-user ID and
the same body the legitimate user would send. **Do not destructively
modify**. If `PUT /users/{other_id} {role: "admin"}` returns 200,
that's the write path proven — note it, do NOT actually elevate.

Read-IDOR is high; write-IDOR is critical. Read-IDOR-to-admin-write is
"contact the customer ASAP" critical.

### 6. Persist the finding

`report_finding`:

- `severity`: based on (data class) × (read|write) — see the table above.
- `title`: include the endpoint, the ID type, and the blast: `"IDOR on
  GET /api/orders/{id} reads all 12k+ orders; sequential numeric ID"`.
- `cwe_id`: CWE-639.
- `description`: 3-4 sentences — the endpoint, the IDs probed, the count
  reached, the data class observed, whether write is also affected.
- Include 1 sample row from another user (masked: `***@***`).

## Pitfalls

- Don't paste 50 real emails / names / records into the finding. One
  masked sample is enough; the count + projection is what matters.
- A 200 with empty body is not a leak — check the body for actual
  other-user data.
- "I got data" + "I'm an admin in this app" = not IDOR; you're allowed
  to see it. Make sure your session is a regular user role.
- Some APIs return 200 with `{error: "not found"}` for IDs you don't
  own — that's the auth check working. Read the body before claiming.
- Cross-tenant IDOR (tenant boundary, not user boundary) is the worst
  flavor; flag it explicitly in the title.

## Output expectations

- One finding per IDOR pattern (not per ID probed).
- A `remember` note with the canonical proof request and projection.
- Plan item marked `done`.
