# Ingest Reference

> **Related:** [server.md](server.md) for the receiving server & recording proxy ·
> [scanning.md](scanning.md) for `-I`/`-i`/`-T` and the full input-format matrix ·
> [data.md](data.md) for browsing what landed · [loop-read.md](loop-read.md) for the fs mirror

Complete flag reference for `vigolium ingest` — parse traffic from a file, spec,
or stdin and store it as HTTP records, either into the local database or into a
running vigolium server.

`ingest` is the "load traffic, don't scan yet" primitive. To scan on receive,
add `--scan-on-receive` (local) or feed a server started with it (see
[server.md](server.md)).

## Table of Contents

- [ingest](#ingest)
- [Key global flags](#key-global-flags-for-ingest)
- [Local vs Remote Mode](#local-vs-remote-mode)
- [Input formats — one example each](#input-formats--one-example-each)
- [OpenAPI / Swagger spec flags](#openapi--swagger-spec-flags)
- [Combined examples](#combined-examples)

---

## ingest

**Usage:** `vigolium ingest [flags]`

Ingest HTTP requests into the database, either locally or via a remote server.
Responses are fetched by default (source `ingest-cli`); disable with
`--disable-fetch-response` to store request-only records.

### ingest-specific flags

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--server` | `-s` | string | — | Server URL for remote ingestion (omit for local mode) |
| `--dir` | — | string | — | Ingest every matching file in this directory **in one process** |
| `--dir-glob` | — | string | `*` | Filename pattern for `--dir`, e.g. `'*.har'` |

### Batch ingest — N files, ONE process

`-i` is repeatable, and `--dir` walks a directory. Both ingest every source in a
single process against a single database handle:

```bash
# Repeated -i, in the order given.
vigolium ingest -i a.har -i b.har -i c.yaml

# Or point at a directory (non-recursive, sorted, so re-runs are reproducible).
vigolium ingest --dir ./captures --dir-glob '*.har' -I har     # one file or many
```

A failing source does not discard its siblings — one bad HAR in fifty must not
cost the other forty-nine. The command still exits non-zero and names how many
failed.

An empty `--dir` match is a **hard error**: "ingested 0 records" for a typo'd
path is indistinguishable from an empty capture.

> **A batch emits ONE document for the whole run.** `ingest -i a.har -i b.har -j`
> prints a single envelope whose `records_ingested` covers every source, so
> `... -j | jq .records_ingested` is the batch total. The human console prints one "Ingestion completed"
> line for the run, under the `ingesting N source(s) in one process` header.

> Concurrent `vigolium ingest` processes against one SQLite file are safe (every
> open sets `busy_timeout`, WAL, and an immediate write lock, so writers
> serialize instead of failing with `SQLITE_BUSY`). Batch mode is still the right
> shape — it pays one process start and one schema check, not N.

### Key Global Flags for Ingest

| Flag | Description |
|------|-------------|
| `-t <url>` | Base URL / target for the ingested data (required for specs that carry only paths) |
| `-i <file>` | Input file path (`-` for stdin). Repeatable here - see [Batch ingest](#batch-ingest--n-files-one-process) |
| `-I <format>` | Input format. Canonical: `urls`, `nuclei`, `openapi`, `wsdl`, `postman`, `curl`, `burpraw`, `burpxml`, `burpscope`, `har`, `deparos`. Old spellings remain as aliases (`swagger`→`openapi`, `burp`→`burpxml`, `raw`→`burpraw`). `vigolium --list-input-mode` prints them with aliases and examples |
| `-T <file>` | Target-file: one target URL per line (for `urls`/`burpscope` only - a spec goes through `-i`). Repeatable; a comma in the path is literal |
| `--input-read-timeout` | Deadline for reading stdin (default `3m`; `0` really does disable it now, and a negative value is exit `2`). Raise it when piping a multi-GB export through stdin, where the read itself can outlast the default |
| `--scan-on-receive` | After ingesting, scan the records (local mode only). `-S` is a **deprecated alias** here and warns — everywhere else `-S` means `--stateless`. |
| `--spec-url` | Use server URLs from the OpenAPI/Swagger spec |
| `--spec-header` | HTTP header(s) for OpenAPI/WSDL requests (repeatable) |
| `--spec-var` | OpenAPI parameter / WSDL element / Postman `{{variable}}` values as `key=value` (repeatable) |
| `--spec-default` | Default value for required parameters (default: `1`) |
| `--disable-fetch-response` | Store request-only (don't fetch responses) |
| `--scope-origin` | Origin scope mode for filtering |
| `--no-tech-filter` | Disable the tech-stack allowlist (run every module regardless of detected stack; auto-on at `--intensity deep`) |
| `--no-waf-pacing` | Disable proactive CDN/WAF-edge pacing (reactive back-off after a WAF block still applies) |

> **`-i` vs `-T`:** `-i` reads a *spec / export* and expands it into requests;
> `-T` reads a *list of target URLs*, one per line. Pointing `-T` at a YAML spec
> makes every line of that file a target. The only formats that are genuinely
> target lists are `urls` and `burpscope`. See [scanning.md](scanning.md) for the
> full contract.

## Local vs Remote Mode

- **Local mode** (default): ingests directly into the local SQLite database and fetches HTTP responses.
- **Remote mode** (`--server <url>` / `-s`): sends records to a running vigolium server via `POST /api/ingest-http`. Set `VIGOLIUM_API_KEY` (or the server's `--alternative-ingest-key`) for auth.
- `--scan-on-receive` is **ignored in remote mode** — the server decides whether to scan (start it with `--scan-on-receive`; see [server.md](server.md)).

## Input formats — one example each

`-I` selects the parser. Without `-I`, every file format below is detected from
its content (extension ignored; the detection is logged), so `-I` is optional.
A file that is mostly not URLs and matches no format fails with
`input_unparsed` naming the closest format instead of becoming junk targets.

```bash
# urls (default) — a single target, or a file of targets.
vigolium ingest -t https://target.example
vigolium ingest -T targets.txt

# OpenAPI 3.x — expand every operation into a request against the base URL.
vigolium ingest -I openapi -i openapi.yaml -t https://api.target.example

# Swagger 2.0.
vigolium ingest -I swagger -i swagger.json -t https://api.target.example

# WSDL 1.1 / SOAP — expand every bound operation into a SOAP POST. `-I` is
# optional (a .wsdl is content-sniffed); a .svc/.asmx URL auto-fetches its WSDL.
vigolium ingest -I wsdl -i service.wsdl -t https://api.target.example
vigolium ingest -i https://api.target.example/Service.svc

# Burp Suite XML export.
vigolium ingest -I burp -i burp-export.xml

# Burp project-config scope export → expands include rules into seed URLs.
vigolium ingest -I burpscope -i burp-scope.json

# cURL commands (one per line, or a pasted multi-line command).
vigolium ingest -I curl -i requests.txt

# HAR archive (browser DevTools / proxy export).
vigolium ingest -I har -i traffic.har

# Postman collection.
vigolium ingest -I postman -i collection.json

# Nuclei templates (extract request definitions).
vigolium ingest -I nuclei -i templates/

# stdin — pipe any supported format through `-i -`.
cat urls.txt         | vigolium ingest -i -
cat openapi.yaml     | vigolium ingest -I openapi -i - -t https://api.target.example
curl-command-here    | vigolium ingest -I curl  -i -
```

## OpenAPI / Swagger spec flags

Specs often need help resolving base URLs, auth, and required parameters:

```bash
# Use the server URLs declared inside the spec instead of -t.
vigolium ingest -I openapi -i spec.yaml --spec-url

# Attach auth headers for every generated request (repeatable).
vigolium ingest -I openapi -i spec.yaml -t https://api.target.example \
  --spec-header "Authorization: Bearer $TOKEN" \
  --spec-header "X-Api-Key: $KEY"

# Supply concrete values for path/query parameters, with a fallback default.
vigolium ingest -I openapi -i spec.yaml -t https://api.target.example \
  --spec-var userId=42 --spec-var status=active --spec-default 1

# Credentials for the spec's security schemes: bearer (also oauth2 /
# openIdConnect) and basic build the Authorization header; a value already
# starting with "Bearer "/"Basic " is not prefixed twice.
vigolium ingest -i spec.yaml -t https://api.target.example \
  --spec-var bearer=$TOKEN --spec-var basic=user:pass
```

Required parameters with no example, default or usable schema get a
type-shaped placeholder (`1`, `true`, the zero UUID) instead of dropping their
operation; operations that still produce no request are counted in a warning.
Path values are escaped as one segment (`a/b` → `a%2Fb`).

### WSDL / SOAP

A WSDL becomes one SOAP POST per bound operation (SOAP 1.1 with a `SOAPAction`
header, or SOAP 1.2 with `action=` in the content type; document/literal and rpc
styles). The XML body is synthesized from the WSDL's inline XSD types and is
fuzzable by the normal active modules. `--spec-header` and `--spec-var` apply
here too — `--spec-var` overrides a leaf element's placeholder value by its local
name.

```bash
# Endpoint comes from the WSDL's <soap:address>; -t overrides only the host
# (scheme+host from -t, service path from the WSDL) to keep traffic in scope.
vigolium ingest -I wsdl -i service.wsdl -t https://soap.target.example \
  --spec-header "Authorization: Bearer $TOKEN" \
  --spec-var userName=admin

# A live WCF (.svc) or ASMX (.asmx) endpoint — the WSDL is fetched automatically
# (?singleWsdl / ?WSDL), so no local file is needed.
vigolium ingest -i https://soap.target.example/Service.svc
```

WSDL 2.0 and unresolved multi-file `<import>` are not supported — point at a
`.svc` `?singleWsdl` (which inlines schemas) when a WSDL splits its types across
files.

## Combined examples

```bash
# Ingest a spec locally, then auto-scan the generated requests.
vigolium ingest -t https://api.example.com -I openapi -i spec.yaml --scan-on-receive

# Ingest a whole capture folder in one process.
vigolium ingest --dir ./captures --dir-glob '*.har' -I har

# Ingest a Burp export request-only (no response fetching — fast, offline).
vigolium ingest -I burp -i export.xml --disable-fetch-response

# Push a spec to a running server for it to scan (remote mode).
VIGOLIUM_API_KEY=… vigolium ingest -s http://localhost:9002 -I openapi -i spec.yaml

# Ingest into a specific project.
vigolium ingest -I har -i traffic.har --project-name acme-audit

# Load traffic, then browse it (see data.md).
vigolium ingest -I burp -i export.xml
vigolium traffic --source ingest-cli --tree
```

After ingesting, records are queryable with `vigolium traffic` (filter by
`--source ingest-cli` / `ingest-server` / `ingest-proxy`) — see
[data.md](data.md).

## `ingest -j` output

The standard envelope. `items` lists the records the run left in the store (up
to 50; `items_truncated` says more exist), each `{uuid, uuid_short, method, url,
status_code}`, so what landed can be read back by UUID:

```jsonc
{
  "schema_version": 1, "command": "ingest", "items": [{"uuid": "…", "uuid_short": "3f2a9c1e", "method": "GET", "url": "…", "status_code": 200}], "total": 30,
  "records_ingested": 30,         // rows the database now HOLDS
  "records_failed": 0,            // read, but not stored — see below
  "records_skipped": 0,           // dropped on purpose (static asset, out of scope)
  "input_format": "har",          // what was PARSED  (har, burp, openapi, urls…)
  "record_source": "ingest-cli",  // what was STORED in http_records.source
  "duration_ms": 336,
  "query": "vigolium traffic --json -n 20"
}
```

**`records_ingested` is what the database holds**, not what was attempted.
`select count(*) from http_records` after the run equals it.

**`records_failed > 0` exits `1`** with `error.code: "ingest_incomplete"` — a
record was read and could not be stored. Why is in `failure_reasons` (counts) and
`failures` (the first 20, each `{url, reason, detail}`), and the error message
names the dominant reason and its fix:

| Reason | Meaning | Fix |
|---|---|---|
| `blocked` | the answer was a WAF / bot-wall page | `--keep-blocked` stores it, remark `blocked:<reason>`; or `--disable-fetch-response` |
| `fetch_error` | DNS, connect, TLS or timeout | `--disable-fetch-response` stores the request without fetching |
| `quarantined` | the host was quarantined as unresponsive | as above |
| `budget` | `--max-requests[-per-host]` refused the send | raise the budget |
| `store_error` | the database refused the write | check the store (`vigolium db stats`) |
| `out_of_scope` | out of scope with `scope.applied_on_ingest` set | widen the scope |
 `records_skipped` is NOT a failure:
those records were dropped by the static-asset carve-out or by
`scope.applied_on_ingest`, which is the configuration doing its job.

**`input_format` and `record_source` are two different vocabularies** and must
not be crossed: `--source` on a read filters by the *record source*, so
`--source har` matches nothing. This pair replaces a single ambiguous `source`
field that held the input format — if you parsed `.source` here, read
`.input_format` now.
