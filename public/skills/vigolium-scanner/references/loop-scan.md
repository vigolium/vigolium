# The agent loop: Scope, sweep, plan, scan

> **Related:** [agent-loop.md](agent-loop.md) (start here) · [invariants.md](invariants.md) (the `-j` envelope, exit codes) · [flags.generated.md](flags.generated.md)

Steps 1–2 of the loop: find out what is there, sweep a host list, plan with `--dry-run`, then scan and gate.

## Step 1 — Scope

```bash
# What's already in the DB?
vigolium db stats --json

# Is the environment ready (binaries, providers, templates)?
vigolium doctor --json

# What modules exist / match a topic?
vigolium module ls xss
```

## Step 1.5 — Sweep, when the scope is a host list

With more than a handful of targets, probe first and scan what's worth scanning.
`run probe` sends one request per target — no discovery, no fuzzing. With
`--format jsonl` it streams one record per line on stdout (progress goes to
stderr, so `2>/dev/null` or `--silent` gives a clean pipe; `-j` would print the
one scan document instead):

```bash
vigolium run probe -T hosts.txt --format jsonl --no-response -c 50 2>/dev/null > sweep.jsonl

# Alive + interesting, ranked by attack surface:
jq -r 'select(.type=="http_record") | .data
       | select(.status_code < 500)
       | [.surface_score, .status_code, .url, .response_title] | @tsv' sweep.jsonl \
  | sort -rn | head -40
```

Each record carries `status_code`, `response_time_ms`, `response_title`,
`response_words`, `surface_score` (0-100, percent of the surface signals present), `ip`, and the full DNS
answer (`a`/`aaaa`/`cname`). Add `--tls-probe` for the certificate (`tls` object:
version, cipher, subject/SANs, issuer, validity, fingerprints). Field names match
httpx's, so an existing consumer reads them unmodified.

Then scan only the survivors:

```bash
jq -r 'select(.type=="http_record") | .data | select(.surface_score >= 30) | .url' \
  sweep.jsonl > worth-scanning.txt
vigolium scan -T worth-scanning.txt --fail-on high
```

`a`/`aaaa`/`cname`/`tls` are stored per host:port, not per record: `traffic -j`
merges them back onto each row, and `vigolium hosts -j` reads them on their own.

For the survivors, `vigolium fingerprint` answers "what is this origin" in a
bounded number of reads — stack, title, favicon hash, well-known paths, CORS,
OPTIONS, Host-header variants and the not-found baseline — stored for the next
session to read with `vigolium hosts`:

```bash
vigolium fingerprint -T worth-scanning.txt -j --compact
vigolium hosts --format tsv --fields hostname,port,title,technology,soft_not_found
```

## Step 1.75 — Plan before you scan

`--dry-run` on `scan` (and `run <phase>`) resolves the scan exactly as it would
run and prints the plan, sending nothing: no scan UUID, no scan row, no output
file, no wordlist written, no login, no OAST registration; an existing database
is only read.

```bash
vigolium scan -t https://target.example --dry-run -j
vigolium run discovery -t https://target.example --dry-run -j
```

`-j` is a `kind: "scan"` envelope with `dry_run: true`, `items` = the phases and
`plan` = the full plan (the same object `scan.plan` carries and the scan row
stores). What to read in it:

- `phases[]`: every phase in execution order with `enabled`, `disabled_by`
  (`strategy`, `only`, `skip`, `heuristics`, `intensity`, `module_selection`,
  `default` = opt-in, `gate` = a runtime precondition, `flag`, `scope`),
  `sends_target_traffic`, `budget {per_target_ms, phase_ceiling_ms,
  duration_factor, grace_ms, semantics, source}` (`semantics`: `per_target`,
  `per_target_capped`, `phase`, `per_leg`, `per_call`; `source`: `flag`,
  `config`, `factor`, `default`, `floor`), the `pace` fields the phase enforces,
  and `request_cap_enforcement` when `--max-requests` is set.
- `targets {seeded, admitted, rejected, rejected_sample, db_records_in_scope}`:
  scope admission. A seeded target the scope refuses stops the dry run before
  the plan, as it stops the scan: exit `2`, `error.code: out_of_scope`.
- `modules {active, passive, extensions, tier_ceiling, tier_filtered,
  hygiene_suppressed, risk_gated, payloads_gated[], by_scope}`: what runs and
  what the intensity holds back.
- `auth[]`: session names, roles and kinds only, never a secret.
- `discovery` (wordlist tier and line counts, fuzzing and why, recursion,
  jstangle workers, sitemap caps), `harvest`, `param_mining`, `egress`.
- `estimate {low, high, ceiling_by_pace, clamped_to, hits_max_requests,
  by_phase, basis, confidence: "rough"}`. `ceiling_by_pace` (rate limit × the
  time budget) is the only hard number; the rest is a heuristic, explained in
  each `basis`. A `--max-requests` lower than `high` clamps it and names the
  phases that will hit it. `estimate.duration_ms {low, high, basis}` is the
  rough wall-clock range; compare its `high` with your harness's command
  timeout before running in the foreground.
- `warnings[]`: `{code, message}` — `targets_out_of_scope`,
  `unbounded_discovery` (no `--scanning-max-duration` or `--max-requests`),
  `auth_invalid`, `input_file`.

## Step 2 — Scan and gate

```bash
# One URL, JSON scan document to stdout, exit 4 on high+. It attacks only this
# input (stored records of the host need --include-stored) but still writes to
# the active database; add -S to keep nothing.
vigolium scan-url https://target.example --json --fail-on high

# Full pipeline into the DB, gated for CI.
vigolium scan -t https://target.example --fail-on high

# A raw request from stdin (pipeline-friendly).
printf 'GET /api?q=1 HTTP/1.1\r\nHost: target.example\r\n\r\n' \
  | vigolium scan-request --json
```

`scan`, `run`, `scan-url` and `scan-request` under `--json` print **one scan
document** when the scan ends (`kind: "scan"`, `schema_version: 2`), on every
path — direct, `-S`, `-o`, one target or many, success or failure:
`{"scan_uuid","scan_uuids","persisted","status","completeness","stop_reason","reasons","targets":[{"target","method","scan_uuid","admitted","reached","reason","code","detail","resolved_target","scheme_source","findings","duration_ms"}],"targets_not_scanned","phase_outcomes","modules":{"selected","executed"},"counts_by_severity","candidates","observations","errors":[{"code","message"}],"total","items":[…],"items_truncated","query","query_argv"}`.
`items` are finding rows in the `finding -j` shape (plus `request` /
`response_evidence`), highest severity first, capped at `-n/--limit` (default
200); `total`/`counts_by_severity` are exact and `query` (`finding --scan-uuid
<uuid> -j`) lists the rest. An unpersisted finding (`-S`) has no `id` — use
`finding_hash`. `status` is `completed`, `curtailed`, `failed` or
`interrupted`; a failed scan still prints its document with `errors[]` and the
exit code carries the failure. A target that never answered: `reached: false`,
`reason: "unreachable"`, `code` (`refused`, `dns`, …), `stop_reason:
"no_targets_reachable"`, exit `1` (a batch: only when no input answered).
`modules.executed` counts modules that actually ran (`selected` is the
selection). `scan-request` fills `scheme_source`: with no `-t`, absolute-form
line, `:80`/`:443` or same-origin `Origin`/`Referer`, it probes the target
(connect + TLS handshake) instead of assuming `https://`; `--no-scheme-probe`
keeps the old default. `--fields`, `--compact`, `--full-body` and
`--max-output-bytes` shape `items` as on `finding`. `-j` is not the bulk
stream; use `--format jsonl -o <file>` for that.

**Which command?** Use `scan-url` / `scan-request` only when you're confirming
**one specific request** — full params, a deep path, or custom headers you need
sent verbatim. For a bare host/root URL, `scan -t` expands the surface for you.

A full `scan -t` can run well past 30 min (discovery defaults to 1h, spidering
30m, no total cap) — **launch it in the background** and poll the DB, or bound it:

```bash
vigolium scan -t https://target.example --scanning-max-duration 30m --fail-on high
```

For a quick single-phase pass, run it directly: `vigolium run spidering -t <url>`.
