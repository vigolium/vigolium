# Troubleshooting

Common issues encountered when using Vigolium and their solutions.

## WAF/Rate Limiting Blocking Scans

**Symptoms:** Many requests return 403/429 status codes, scan results are incomplete, or the target becomes unresponsive.

**Solutions:**

Reduce concurrency to slow down request volume:

```bash
vigolium scan -t https://example.com -c 10
```

Apply a rate limit (requests per second):

```bash
vigolium scan -t https://example.com -r 50
```

Use the lite strategy, which uses fewer payloads and a less aggressive scanning profile:

```bash
vigolium scan -t https://example.com --strategy lite
```

You can combine these options for heavily protected targets:

```bash
vigolium scan -t https://example.com --strategy lite -c 5 -r 20
```

## Browser Not Found (Spidering)

**Symptoms:** Spidering phase fails with errors about missing Chromium or browser binary.

**Solutions:**

Chromium is automatically downloaded on first use to `~/.cache/spitolas/chromium-<version>/`. If this download is blocked by network restrictions:

1. Build an embedded-browser binary with
   `make deps-chrome && make build-embedded`.
2. Alternatively, skip the spidering phase entirely:

```bash
vigolium scan -t https://example.com --skip spidering
```

## Scope Mismatch (No Results)

**Symptoms:** Scan completes but produces zero findings or skips all requests.

**Solutions:**

Verify the target URL matches the configured scope. The scanner only tests URLs that fall within the defined scope.

Check the current scope configuration:

```bash
vigolium config ls scope
```

Explicitly set the scope to include your target by updating the config:

```bash
vigolium config set scope.host.include "*.example.com"
```

Ensure the target URL scheme (http vs https) and hostname match what the scope expects. Subdomains are not included by default unless a wildcard pattern is used.

## OAST Not Working

**Symptoms:** No out-of-band findings are reported, even for vulnerabilities that typically produce OAST interactions (e.g., blind SSRF, blind XXE).

**Solutions:**

OAST requires outbound DNS and HTTP connectivity from the target application to the OAST callback server. Check that:

1. The scanned application can make outbound DNS queries.
2. The scanned application can make outbound HTTP requests.
3. No firewall rules block these outbound connections.

OAST is optional. The scanner still produces findings without it using in-band detection methods. OAST adds an extra layer of detection for blind/out-of-band vulnerabilities, but its absence does not prevent the scanner from working.

## High Memory Usage on Large Targets

**Symptoms:** The scanner process consumes excessive memory, the system becomes slow, or the process is killed by the OS.

**Solutions:**

Use the lite strategy to reduce the number of payloads and checks:

```bash
vigolium scan -t https://example.com --strategy lite
```

Run only the dynamic-assessment phase to skip discovery and spidering, which can generate large numbers of URLs:

```bash
vigolium scan -t https://example.com --only dynamic-assessment
```

Reduce concurrency to limit the number of in-flight requests and queued items:

```bash
vigolium scan -t https://example.com -c 5
```

Skip discovery to avoid large wordlist-based scans that produce many URLs:

```bash
vigolium scan -t https://example.com --skip discovery
```

## Scan Takes Too Long

**Symptoms:** Scan runs for hours without completing, or appears stuck in a particular phase.

**Solutions:**

Use the lite strategy for faster scans with fewer checks:

```bash
vigolium scan -t https://example.com --strategy lite
```

Limit discovery time to prevent long-running content discovery:

```bash
vigolium scan -t https://example.com --discover-max-time 5m
```

Limit spidering time:

```bash
vigolium scan -t https://example.com --spider-max-time 5m
```

Run only the dynamic-assessment phase if you already have traffic recorded:

```bash
vigolium scan -t https://example.com --only dynamic-assessment
```

Combine options for the fastest possible scan:

```bash
vigolium scan -t https://example.com --strategy lite --skip discovery --skip spidering
```

## Database Issues

**Symptoms:** Errors related to database access, corrupted data, or migration failures.

**Solutions:**

The default database is SQLite at
`~/.vigolium/database-vgnm.sqlite`.

To switch to a different database location:

```bash
vigolium scan --target https://example.com --db /path/to/other.db
```

To reset the database and start fresh:

```bash
vigolium db reset --force
```

`--db` selects an alternate SQLite file. Configure PostgreSQL with
`database.driver: postgres` and the `database.postgres` fields in
`vigolium-configs.yaml`; `--db` is not a PostgreSQL DSN flag.

## Agent Mode Not Working

**Symptoms:** `vigolium agent` commands fail with errors about missing backends, connection issues, or authentication failures.

**Solutions:**

1. **Inspect the active olium provider.** All query, Swarm, Autopilot, and
triage calls use the in-process olium engine:

```bash
vigolium agent --list-agents
vigolium config ls olium
vigolium doctor --json
```

2. **Check the provider endpoint and credentials.** The shipped default is an
`openai-compatible` endpoint at local Ollama. Start that endpoint and choose a
tool-capable model, or select another provider:

```bash
vigolium config set agent.olium.provider openai-codex-oauth
vigolium config set agent.olium.oauth_cred_path ~/.codex/auth.json
```

For key providers, set `OPENAI_API_KEY` or `ANTHROPIC_API_KEY`; the
`anthropic-cli` provider is the one that requires a local `claude` binary.

3. **Verify session directory permissions.** Agent sessions are stored under
`~/.vigolium/agent-sessions/` by default. Ensure it is writable, then inspect a
failed run with `vigolium agent session <uuid>` and `vigolium log <uuid>`.

See [Set Up an AI Provider](getting-started/setup-agent.md) for all supported
providers and credential fields.

## Permission Denied on Build

**Symptoms:** `make build` or `make install` fails with permission errors when writing to `$GOPATH/bin`.

**Solutions:**

Ensure `$GOPATH/bin` exists and is writable:

```bash
mkdir -p "$(go env GOPATH)/bin"
chmod u+w "$(go env GOPATH)/bin"
```

Always use `make build` instead of `go build`. Direct `go build` bypasses version injection and may produce incorrect binaries:

```bash
# Correct
make build

# Incorrect - do not use
go build -o vigolium .
```

The `make build` command outputs the binary to `bin/vigolium` and installs it to `$GOPATH/bin`. If you only need the binary locally without installation, the built binary is available at `bin/vigolium` after running `make build`.
