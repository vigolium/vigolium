# e2e-expect: expectation e2e kit

End-to-end scenarios that assert two things: what vigolium reported, and what
the target actually received on the wire. The tests use the `e2e` build tag,
so `make test-e2e` runs them alongside `test/e2e`.

| Command | Runs |
| --- | --- |
| `make test-e2e-expect` | Everything (about 35 minutes, needs Docker) |
| `make test-e2e-expect-lab` | The lab half only (`-short`: live tests skip; about 5 minutes, no Docker) |
| `make test-e2e-expect-live` | The live half only: `TestLive_*` against Docker targets |
| `make e2e-expect-lab` | Serves the lab standalone for hands-on testing |

## Lab half (no Docker)

`lab/` is a fake target that runs inside the test process:
- **Planted bugs:** `VulnApp` serves open redirect, XSS, SQL error, path traversal, SSTI and command injection, each paired with a safe twin.
- **Hostile endpoints:** `Minefield` adds endpoints that hang, tarpit, reset, lie about length, break chunking, send huge or gzip-bomb bodies, or loop redirects.
- **Non-HTTP and faults:** raw TCP listeners (SSH banner, garbage, silent), plus fault switches (`Faults.SetDown/SetLatency/SetStatus`).
- **Ledger:** every server records each request. It reports count, open requests, peak concurrency, the busiest 1-second window, and the status mix.

Scenarios: `scan_test.go` (in-process runner), `fuzz_test.go`, `probe_test.go`, `lifecycle_test.go` (built binary: SIGINT, double SIGINT, `--resume-scan`).

## Live half (Docker)

`live_test.go` starts a fresh container per test (Juice Shop, VAmPI), bound to 127.0.0.1. Every scan goes through a lab reverse proxy (`app.Base`), so a live run has the same ledger as a lab one. `live_scenarios_test.go` covers:

| Scenario | Command | Expectation |
| --- | --- | --- |
| Probe | `run probe` | one `probe` record, no findings |
| Fingerprint | `run fingerprint` | host facts (CORS, favicon) in the `-j` document; golden findings |
| Discovery | `run discovery` | `/ftp`, `/metrics`; golden paths and request count; no `/true/` endpoints; no brute-forcing under file names |
| Spidering | `run spidering` | reaches `/rest/products/search`; only `spidering` records |
| Module-scoped dynamic assessment | `run dynamic-assessment -m …` and `scan --only dynamic-assessment -m …` | the SQLi is found; only selected active modules report; the two commands agree |
| Stateless | `scan -S --format jsonl -o` | `--db` is refused; the export has traffic and the finding; nothing persisted; no scratch database left in TMPDIR |
| Native scan | `scan` (skipping known-issue-scan and external harvest) | golden findings, paths and records; the target survives |
| VAmPI ingestion | `run ingestion -i spec -I openapi` | 14 answered records, all methods, no findings |
| VAmPI spec scan | `scan -i spec --only dynamic-assessment -m sqli…` | SQLi on `/users/v1/{username}` |

Each scenario checks:
- the exit code and the `-j` contract (`ok`, `status`, `completeness`);
- what was stored, read straight from the run's database file;
- that the target still answers afterwards. The proxy's request count, peak concurrency and the container's memory are logged.

Environment variables:
- `E2E_EXPECT_BIN` reuses a built binary.
- `E2E_EXPECT_BROWSER` points the spider at a Chromium. Otherwise the kit looks in rod's cache and for a system Chrome, and skips spidering if it finds none.

## Contracts

- **Expected results:** `testdata/expect.json` holds the golden entries. Regenerate with `go test -tags e2e ./test/e2e-expect/ -run <Test> -args -update-expect`.
  - **Lab entries** are exact: the set of findings at Low or above must match, and the request count must stay within ±25%.
  - **Live entries** only fail on losing ground: a golden finding missing, more than 10% of golden paths missing, fewer than 60% of golden records, or a request count outside ±25%. New findings are logged.
- **Known defects:** `knownDefects` (in `scan_test.go`) lists defects the kit reproduces today, each with a reason. While an entry is listed, `expectKnown` only logs it. A deterministic defect that stops reproducing fails the test until its entry is removed; one marked `intermittent` is only logged when seen.
- **Safe twins:** findings at Low or above on a safe twin or a minefield endpoint are false positives.
- **Goroutine leaks:** `goleak` runs in `TestMain`. Its ignore list names the process-lifetime singletons, plus one known issue.
