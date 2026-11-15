# The agent loop: Hand off

> **Related:** [agent-loop.md](agent-loop.md) (start here) · [invariants.md](invariants.md) (the `-j` envelope, exit codes) · [flags.generated.md](flags.generated.md)

Step 5: Burp, curl and reports; and reading the output of AI agent runs.

## Step 5 — Hand off

### To Burp, for manual work

All Burp handoffs need the bridge extension's loopback listener via
`-B`/`--burp-bridge-url` or `$VIGOLIUM_BURP_BRIDGE_URL`.

```bash
# A finding's evidence → Burp Organizer (default) or a Repeater tab
vigolium finding --id 42 --push-to-burp -B http://127.0.0.1:9009
vigolium finding --severity high --to-repeater -B http://127.0.0.1:9009

# A replayed request → Repeater / Organizer / Site map
vigolium replay -u <uuid> --to-repeater -B http://127.0.0.1:9009
vigolium replay -u <uuid> --to-organizer --notes "IDOR candidate" -B http://127.0.0.1:9009

# Fuzz matches → the Organizer (Burp re-issues each)
vigolium fuzz -u <uuid> --fuzz params --class sqli --matches-to-organizer -B http://127.0.0.1:9009
```

`--send-via-burp` (on `replay` / `fuzz` / `finding`) routes the actual send
through Burp's engine byte-for-byte. Pair it with `--http-mode http1` for
smuggling/desync work so `auto` doesn't reframe the request.

Reading Burp's live history, Site map sync, limits, and the full flag surface:
**[burp.md](burp.md)**.

### As a curl command

```bash
vigolium finding --id 42 --curl                 # the finding's proving request
vigolium finding --id 42 --curl-all -j          # every linked record, as items
vigolium traffic --uuid <id> --curl --redact-auth
```

The URL comes from the stored scheme/host/port, arguments are POSIX
single-quoted (safe for `sh -c`), and a binary body is piped through
`base64 --decode`. Under `-j` each item carries `curl` (the shell line) and
`argv` (the exec vector). `traffic --curl` renders at most 20 without `-a`.
Nothing is sent. Details: [data.md](data.md#traffic---curl--finding---curl).

### To a report

```bash
vigolium finding --id 42 --markdown                 # Markdown to stdout
vigolium export --format html -o report.html        # interactive ag-grid report
vigolium export --format jsonl -o out.jsonl         # bulk stream
```

Under `-S/--stateless`, add `--compact` to `--markdown` so the response is
windowed at the match instead of dumping a whole page.

## Agentic scans

These run an LLM-driven scan into the DB. With `--json`, the live agent stream
goes to **stderr** and one run document is printed to **stdout** at the end:

```bash
vigolium agent audit --source . --intensity balanced --json
vigolium agent autopilot -t https://target.example --json
vigolium agent swarm -t https://target.example --json
vigolium agent query --prompt-template security-code-review --source . --json
```

Run document (autopilot / swarm / audit; `kind: "scan"`, the scan document's
spine):

```json
{ "kind": "scan", "ok": true, "agentic_scan_uuid": "…", "mode": "autopilot",
  "session_dir": "…", "status": "completed", "completeness": "complete",
  "persisted": true, "usage": {"input_tokens": 0, "output_tokens": 0, "cost_usd": 0},
  "budget": {"max_commands": 750, "token_budget": 0, "max_cost_usd": 0, "exhausted": false},
  "total": 7, "counts_by_severity": {"critical":1,"high":3, …},
  "items": [ … top 20 finding views … ], "errors": [], "warnings": [],
  "query": "vigolium … finding --agentic-scan <uuid> -j" }
```

Branch on `status`: `completed` / `completed_with_warnings` (exit 0);
`timed_out`, `budget_exhausted`, `completed_with_errors` (exit **5**, the run's
work is still in the DB); `failed` / `cancelled` (exit 1). The database spells
`timed_out` as `timeout`. With no DB the document still prints,
`persisted: false`. `provider_missing` / `preflight_failed` (exit 1, error
envelope) mean nothing ran. Budgets: `--max-commands`, `--token-budget`,
`--max-cost-usd`, `--max-duration`. `agent audit` needs `--source` (`.` for
cwd); `agent autopilot` runs a nested `--audit`/`--piolium` harness only when
asked. `agent triage <id> -j` is a mutation document (`--no-write` to report
only; a `false_positive` keeps its severity). `agent query` / `triage` print
their `agentic_scan_uuid` on stderr.

Run the `query` line to pull full results. `--agentic-scan` expands to the whole
run tree (audit driver legs, swarm sub-runs), so one UUID returns every finding
the run produced.

Full flags, intensities, and providers: `references/agent-modes.md`.
