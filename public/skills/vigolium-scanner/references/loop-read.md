# The agent loop: Read the results

> **Related:** [agent-loop.md](agent-loop.md) (start here) · [invariants.md](invariants.md) (the `-j` envelope, exit codes) · [flags.generated.md](flags.generated.md)

Step 3: survey and drill into what a scan stored, from the database, an export or a filesystem tree.

## Step 3 — Read the results

```bash
# Compact triage list of high+ findings, only the fields you need.
vigolium finding --min-severity high --json --compact \
  --fields id,severity,module_id,url,matched_at

# One finding, fully self-contained (finding + linked request/response).
vigolium finding --id 42 --json --with-records

# Narrow a search to the Nth match by list position (1-based).
vigolium finding --search 'Reverse Proxy' --pick 2 --raw

# The endpoint inventory: one row per origin + path template (/users/{int}),
# methods, params by location, status mix, auth split, live finding counts.
vigolium endpoints --host api.example.com --json
vigolium endpoints --source jstangle --json        # routes known only from JS

# Parameters with value-type histograms: IDOR candidates in one call.
vigolium params --type integer,uuid,sequential_id --json

# Survey raw records without bodies — cheap.
vigolium traffic --json --compact \
  --fields uuid,method,url,status_code,response_content_type

# Only what one scan stored first (records are stamped on insert).
vigolium traffic --scan-uuid <uuid> --json --compact

# Everything for one record.
vigolium traffic search-term --json --full-body -n 1
```

`endpoints` and `params` aggregate in one streaming pass over light columns
(never bodies), through the same filters as `traffic`, so they are safe on a
large corpus. Their `-j` items and caps are in
[data.md → endpoints](data.md#endpoints) / [params](data.md#params). An empty
`--scan-uuid` read for a scan with no stamped records carries
`provenance_warning: "scan_uuid_not_stamped"` (it predates stamping — use the
`--from/--to` window in `provenance_detail`), not a silent empty list.

Filters shared by `finding` / `traffic` / `db ls`: `--host --path --method
--status --severity --min-severity --from/--to --search --scan-uuid
--agentic-scan --module-type -n/--limit --offset --sort --asc`.

`--search` / `--header` / `--body` span the full request/response corpus (URL,
path, headers, body). Each has an inverse — `--exclude-search` (repeatable,
AND-combined: a row drops if ANY term matches), `--exclude-header`,
`--exclude-body`:

```bash
vigolium traffic --search api --exclude-search /health --exclude-body heartbeat
```

Finding output shape:

```json
{ "schema_version": 2, "command": "finding", "kind": "read", "ok": true,
  "project_uuid": "…", "total": 39, "offset": 0, "limit": 100,
  "items": [ { "id": 2, "finding_hash": "…", "severity": "high", "module_id": "…",
               "vuln_class": "sqli", "url": "…", "status": "draft", "matched_at": ["…"],
               "response_evidence": "…<match>…" } ] }
```

`vuln_class` is the finding's exact class, the routing key: one stable
snake_case name per kind of bug, declared per module (`module ls -j` rows carry
the same field; `multiple` there means each finding names its own). Route on it,
not on `module_id` substrings: `xss_blind` (an out-of-band script fetch, proven
by the callback) is not `xss_reflected` (proven by the response) or
`xss_stored`/`xss_dom`. Vocabulary: `sqli`, `nosqli`, `cmdi`, `code_injection`,
`ssti`, `ssrf`, `xxe`, `lfi`, `ldap_injection`, `xpath_injection`,
`ssi_injection`, `esi_injection`, `smtp_header_injection`, `crlf_injection`,
`host_header_injection`, `deserialization`, `prototype_pollution`,
`file_upload`, `mass_assignment`, `csv_injection`, `prompt_injection`, `rce`,
`xss_reflected`, `xss_stored`, `xss_blind`, `xss_dom`, `csti`,
`client_prototype_pollution`, `dom_clobbering`, `client_path_traversal`,
`css_injection`, `jsonp_callback`, `open_redirect`, `clickjacking`,
`reverse_tabnabbing`, `postmessage`, `idor`, `bfla`, `auth_bypass`,
`acl_bypass`, `default_credentials`, `jwt`, `session_management`,
`oauth_misconfig`, `saml`, `csrf`, `cswsh`, `cors_misconfig`,
`rate_limit_bypass`, `user_enumeration`, `password_reset_poisoning`,
`business_logic`, `request_smuggling`, `cache_poisoning`, `cache_deception`,
`subdomain_takeover`, `bucket_takeover`, `cloud_storage_exposure`,
`padding_oracle`, `race_condition`, `dos`, `dns_rebinding`, `proxy_trust`,
`transport_security`, `security_headers`, `cookie_security`, `weak_crypto`,
`supply_chain`, `info_disclosure`, `data_exposure`, `sensitive_file`,
`source_disclosure`, `source_map_exposure`, `secret_exposure`,
`directory_listing`, `debug_exposure`, `admin_exposure`, `api_docs_exposure`,
`exposed_service`, `misconfiguration`, `outdated_component`, `fingerprint`,
`signal` (an analysis lead, not a bug), `multiple` (module rows only). Absent
on a known-issue template or imported finding. Add-only: ignore a value you do
not know.

`claimed_severity` appears when the stored `severity` is lower than the module
asked for: a Tentative finding files at most `suspect`, and the claim (`high`,
…) stays here. Weigh it as the module's opinion, never as proof.

## Reading exports without a database

`finding` and `traffic` can read a file directly instead of your project DB.
`-S/--stateless` requires `--db` and turns project scoping **off**, so every row
in the file is shown. Nothing is written to your project DB (a JSONL source is
loaded into a throwaway scratch SQLite **file**, deleted on exit — it was
in-memory once, and a large export did not fit). An explicit `--project-uuid`
(or `$VIGOLIUM_PROJECT_UUID`) still filters a stateless read.

```bash
vigolium finding -S --db ./scan-target.jsonl --min-severity medium
vigolium traffic -S --db ./scan-target.jsonl --status 500 -n 20
vigolium finding -S --db ./run.sqlite --json --with-records
```

**Pin a session DB with `$VIGOLIUM_DB_PATH`** to avoid repeating `--db` on every
command. The open order is `--db` → `$VIGOLIUM_DB` → `$VIGOLIUM_DB_PATH` →
`database.sqlite.path` in config → the built-in default. `$VIGOLIUM_DB` is
exactly `--db` from the environment (project scoping stays on); it is what an
agent run hands the `vigolium` commands its bash tool runs, alongside
`$VIGOLIUM_PROJECT_UUID`, `$VIGOLIUM_CONFIG` (`--config` from the environment)
and `$VIGOLIUM_BIN`. Setting it also makes **read** commands
(`finding`/`traffic`/`fuzz -u`) treat that file as a stateless source — project
scoping off, same as `-S --db` above — while writes still go to it. It never
turns a *scan* stateless (that would collide with `--db`).

```bash
export VIGOLIUM_DB_PATH=~/scans/acme.sqlite
vigolium finding --min-severity high      # reads acme.sqlite, scoping off
vigolium scan -t https://acme.example     # writes into acme.sqlite
```

The scoping-off flip is conditional: it applies once the pinned file **exists and
is a usable vigolium store**. Run that `finding` before the first scan of the
session and the read stays project-scoped against a store it just created — which
is the right behavior (it prints an empty table instead of erroring), but means
`project_scoped` is the field to check, not something to assume. A pin that can
never *become* a database — a directory, or a parent dir that cannot be created —
is a hard error rather than a silent fall-through to the shared default; a path
that merely does not exist yet is fine.

A stateless scan emits that `.sqlite` directly with `--format sqlite` (aliases
`sqlite3`, `db`) — it dumps the per-run DB via `VACUUM INTO`, fully
checkpointed, no WAL/SHM sidecars:

```bash
vigolium scan -S --format sqlite,html -o scan -t target.example
vigolium scan -S --format sqlite -o run --split-by-host -P 4 -T targets.txt
vigolium finding -S --db ./run-target.example.sqlite --min-severity high
```

**Merging** foreign databases is the companion operation — `vigolium import`
folds them into one DB (lossless, idempotent, deduped on natural keys; each row
keeps its original `project_uuid`):

```bash
vigolium import other-vigolium-scan.sqlite
vigolium import --db combined.sqlite --glob-db 'scans/*.sqlite'
vigolium -j import --db combined.sqlite other-scan.sqlite   # per-table merge summary
```

Fan out with `scan -S --format sqlite`, merge back with `import`. A Postgres
destination is rejected — the merge is SQLite-to-SQLite.

## Filesystem tree output

When you'd rather `ls`/`grep`/`jq` a scan than query a DB, export a flat tree.
Available on `scan`/`scan-url`/`scan-request`/`run`, `export`, and `db export`.

```bash
vigolium export --format fs -o run                    # whole DB
vigolium scan-url https://t/ -S --format fs -o run    # straight from a scan
vigolium scan -t https://t/ --format jsonl,fs -o run  # alongside other formats
```

Two sibling dirs off the `-o` base (defaults to `vigolium-traffic/` +
`vigolium-findings/` in the cwd). Ids are zero-padded and assigned in `sent_at`
order, so re-exports are reproducible:

```
run-traffic/
  index.json                 # [{id,host,path,method,url,status,content_type,bytes,finding}, …]
  <host>/0001.req            # "@target https://<host>" line, then the raw request
  <host>/0001.resp.headers   # status line + response headers
  <host>/0001.resp.body      # response body, gzip-decoded so it greps clean
run-findings/
  index.json                 # [{id,host,path,severity,confidence,module,title,url,traffic}, …]
  <host>/0001.md             # the finding, cross-linked to ../../run-traffic/<host>/0001.req
```

`index.json` is the entry point — one `jq` maps every id to its url/status and to
the file holding the bytes, so you never guess paths. The `finding` field on a
traffic row is the top severity of any finding touching that request. A `.req`
file is directly replayable by stripping line 1.

`--omit-response` drops the `.resp.*` files. `--split-by-host` is a no-op here
(fs already splits by host).

### Live mirror from the ingestion server

To watch traffic land as files while another tool (Burp, a proxy,
`vigolium ingest`) feeds the server:

```bash
vigolium server --mirror-fs ./mirror        # config: server.mirror_fs_path
```

Every ingested record and finding is written to `./mirror/traffic/<host>/…` and
`./mirror/findings/<host>/…` as it is saved to the DB. Same layout as
`--format fs`, except the indexes are append-only **`index.jsonl`** (one object
per line — tail/grep it live) and per-host ids resume across restarts. It runs on
a background goroutine that never blocks the DB save, and is
server-ingestion-only — CLI scans are unaffected.
