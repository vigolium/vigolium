---
name: ssrf-to-internal-service-breach
description: Escalate a suspected or confirmed Server-Side Request Forgery into proof of internal-service access — cloud metadata, internal-only APIs, database greetings, or redacted-but-fetchable HTTP. Use when a parameter takes a URL (image proxy, webhook, fetcher, URL preview, PDF render) and the server reaches outbound on your behalf, or when an audit finding tags CWE-918. Confirms reachability via OAST, then walks targeted internal endpoints, ending with a finding sized by the highest-value asset reached.
license: MIT
allowed-tools:
  - query_records
  - inspect_record
  - replay_request
  - send_raw_http
  - oast_mint
  - oast_poll
  - attack_kit
  - report_finding
  - update_finding
  - remember
  - update_plan
---

# SSRF → Internal Service Breach

You have a parameter or endpoint that makes the server fetch a URL of
your choosing. Your job is to prove the server reaches an internal
target you, the external user, can't. Persist a finding sized by what
you actually reached, not by the existence of the SSRF.

## When this skill applies

- A request parameter is a URL: `?url=`, `?image=`, `?webhook=`,
  `?callback=`, `?fetch=`, `?source=`, `?preview=`.
- An endpoint clearly fetches on behalf of the user: PDF renderers,
  link preview / OG-tag fetchers, OAuth callback verifiers, image
  thumbnailers, RSS importers, SSO redirect handlers.
- The response includes a fetched body excerpt, content-length, status,
  error string, or response time that varies with the URL you supply.
- Audit finding: CWE-918.

## Workflow

### 1. Confirm outbound reachability

Mint a canary with `oast_mint` (kind: `ssrf-probe`). Inject the canary
URL into the suspect parameter via `replay_request`. Poll with
`oast_poll` for 30-60 seconds.

- **HTTP callback observed** → server reaches your URL via HTTP. SSRF
  confirmed with HTTP egress.
- **DNS callback only** → SSRF confirmed but DNS-only (a strict egress
  filter dropped the HTTP request after the lookup). Still useful as
  exfil channel, but limits what you can do.
- **No callback** → either no SSRF, or filtered, or no internet egress
  from the server. Move to step 2's targeted probes anyway — some SSRFs
  only work against internal hosts.

`remember` the result as `ssrf-egress`.

### 2. Probe metadata services

Cloud metadata is the highest-impact target. Try in order; stop on the
first hit:

- **AWS IMDS v1**: `http://169.254.169.254/latest/meta-data/`
- **AWS IMDS v2** (token-flow): if v1 returns 401, you need a PUT to
  `/latest/api/token` first — most basic SSRFs can't do that, so skip.
- **GCP**: `http://metadata.google.internal/computeMetadata/v1/`
  (needs header `Metadata-Flavor: Google`; some SSRFs let you set
  extra headers via the URL fragment or a chained redirect).
- **Azure**: `http://169.254.169.254/metadata/instance?api-version=2021-02-01`
  (needs `Metadata: true` header).
- **DigitalOcean**: `http://169.254.169.254/metadata/v1/`
- **Alibaba**: `http://100.100.100.200/latest/meta-data/`

Look in the response for `iam/security-credentials/` (AWS), `project/`
(GCP), `instance/` (Azure). Credentials in metadata = critical
finding immediately.

### 3. Probe internal hosts and ports

If metadata doesn't reach (private cluster, no cloud), pivot to common
internal services. Use the URL parameter to hit `http://127.0.0.1:<port>/`
and `http://localhost:<port>/`:

- 6379 — Redis (try `info` via gopher://, or just observe greeting).
- 5432 — PostgreSQL (TLS handshake byte vs HTTP 400 distinguishes).
- 27017 — MongoDB (no HTTP, but error message differs).
- 9200 / 9300 — Elasticsearch (returns JSON cluster info on `/`).
- 8500 — Consul (`/v1/agent/self`).
- 6443 / 10250 — Kubernetes API / kubelet (often `Unauthorized` but
  reachable confirms exposure).
- 8080, 8081, 9090, 3000 — common dev/internal admin panels.

For TCP-only services (Redis, Postgres), `send_raw_http` lets you send
raw bytes if the SSRF supports `gopher://` or `dict://` schemes — most
do not. If only HTTP works, just confirming a 4xx/5xx with a
service-specific error string is enough to size the exposure.

### 4. Probe internal HTTP services and admin panels

`oast_mint` records prior crawls' hostnames. If you've seen
`internal.app.local`, `admin.staging`, `prometheus`, `grafana`,
`vault`, `consul` in any prior `query_records` output, try them via
the SSRF. Note the response.

### 5. Extract one credential / one config

If metadata or an admin panel returned data, extract ONE concrete
high-value item:

- One IAM access key + secret (AWS / GCP).
- One database connection string from a config endpoint.
- One service token from `/vault/v1/...` or `/api/admin/users/me`.
- One Kubernetes service account token.

Mask the secret in the finding (`AKIA****...****ABCD`). **Do not use
the credential.** Reaching it is the proof; the next step (using it)
is post-engagement work, not part of the audit.

### 6. Persist the finding

`report_finding`:

- `severity`:
  - `critical` if you reached cloud metadata credentials, a service
    token, or a database with admin connectivity.
  - `high` if you reached an internal HTTP service or admin panel.
  - `medium` if SSRF is confirmed (OAST callback) but every internal
    target was filtered.
- `title`: name the worst asset reached: `"SSRF in image-proxy reaches
  AWS IMDS; leaks IAM role credentials"`.
- `cwe_id`: CWE-918.
- `description`: 3-4 sentences — the parameter, the egress confirmation
  (HTTP callback observed), the highest-value internal target reached,
  and one masked sample of what was extracted.

## Pitfalls

- Some apps fetch via a sandboxed worker (Lambda, Cloud Run); the
  metadata may belong to the worker, not the main app — still a
  finding, just scope the title accordingly.
- DNS rebinding attacks can bypass IP-based filters that allow only
  public IPs; if a literal `169.254.169.254` is blocked, try a
  rebinding domain — but only with operator authorization (it
  involves outside infra).
- A response that "echoes the fetched body back to you" is great; one
  that "just returns 200/OK with no body" is harder to size — fall
  back to time-based / OAST-based confirmation.
- gopher:// / dict:// are blocked by most modern HTTP clients (Go's
  net/http, Node fetch). Don't burn time on gopher unless the target
  is on libcurl / PHP.

## Output expectations

- One `report_finding` per SSRF, severity matching what you reached.
- A `remember` note with the egress proof and the highest-value
  request used (key: `ssrf-proof`).
- Plan item marked `done`.
