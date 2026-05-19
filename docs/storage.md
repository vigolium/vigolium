# Cloud Storage

Vigolium can read and write to S3-compatible object storage so scan inputs, exports, and result bundles can flow between machines, CI runs, and the server. This guide covers configuration, the `gs://` URL scheme, the `vigolium storage` subcommands, and the storage-aware flags on `import`, `export`, `scan`, and the agent commands.

## What it does

- **Project-scoped object access.** Every key is prefixed with the active project's UUID, so two projects sharing the same bucket cannot read each other's data.
- **S3-compatible.** A single minio-go-based client talks to GCS (HMAC), S3, or self-hosted MinIO. Choose the driver in config; the rest is the same.
- **`gs://` URLs everywhere.** `vigolium import` and `vigolium export -o` accept `gs://<project-uuid>/<key>` directly — downloads to a temp file before importing, uploads from a temp file after exporting.
- **Result auto-archival.** `vigolium scan --upload-results` and the agent commands' `--upload-results` flag tar+gzip the result tree and push it to a conventional key under `native-scans/` or `agentic-scans/`.

## Enabling storage

Storage is **disabled by default**. Enable it in `~/.vigolium/vigolium-configs.yaml`:

```yaml
storage:
  enabled: true
  driver: gcs            # gcs | s3 | minio  (default: gcs)
  bucket: my-vigolium-bucket
  region: us-central1    # bucket region
  access_key: ${STORAGE_ACCESS_KEY}
  secret_key: ${STORAGE_SECRET_KEY}
  use_ssl: true          # default: true
  path_style: false      # default: false (set true for MinIO)
  endpoint: ""           # auto-detected for gcs/s3; required for minio
```

Endpoint defaults:
- `gcs` → `storage.googleapis.com` (uses HMAC keys, not service-account JSON)
- `s3` → `s3.amazonaws.com`
- `minio` → no default; you must set `endpoint` (e.g. `minio.example.com:9000`)

Required fields when enabled: `bucket`, `access_key`, `secret_key`. For MinIO, `endpoint` is also required.

### Toggling at runtime

The `VIGOLIUM_STORAGE_ENABLED` env var overrides the YAML `enabled` setting:

```bash
VIGOLIUM_STORAGE_ENABLED=true  vigolium storage ls    # force-enable for one command
VIGOLIUM_STORAGE_ENABLED=false vigolium scan --upload-results https://target  # force-disable
```

Truthy values: `1`, `true`, `yes`, `on`. Falsy: `0`, `false`, `no`, `off`. Unset means "use the YAML config".

## The `gs://` URL scheme

```
gs://<project-uuid>/<key>
```

- `<project-uuid>` is the Vigolium project UUID, **not** a GCS bucket name. The bucket comes from `storage.bucket` in config; the project UUID is the *prefix inside* that bucket.
- `<key>` is the object key within the project. May contain `/` for nested paths. Path traversal (`..`, leading `/`, backslashes) is rejected.

Example: with `storage.bucket: my-vigolium-bucket`, the URL `gs://abc-123/imports/foo.tar.gz` resolves to the S3 object `s3://my-vigolium-bucket/abc-123/imports/foo.tar.gz`.

When you pass a `gs://` URL whose project UUID differs from the active project, Vigolium logs an info-level notice but still proceeds — useful for cross-project copies, but worth noticing.

## Output placeholders

In any `-o` flag that writes to storage (or locally), two placeholders are expanded:

- `{ts}` → UTC timestamp `YYYY-MM-DDTHH-MM-SSZ` (filename-safe)
- `{project-uuid}` → active project UUID

```bash
vigolium export --format html -o gs://{project-uuid}/exports/scan-{ts}.html
# → gs://<active-project>/exports/scan-2026-04-26T12-34-56Z.html
```

## Conventional key prefixes

Vigolium uses a small set of conventional prefixes inside each project. You can write to other prefixes freely; these are the ones the tooling auto-targets:

| Prefix | Used by | Contents |
|---|---|---|
| `ugc/<filename>` | `vigolium storage upload` (default key) | Free-form user uploads |
| `imports/<basename>-<ts>.<ext>` | `vigolium import --upload` (default key) | Bundles of import sources |
| `native-scans/<scan-uuid>/results.tar.gz` | `vigolium scan --upload-results` | Native scan output bundle |
| `agentic-scans/<run-uuid>/results.tar.gz` | `vigolium agent {autopilot,swarm,archon} --upload-results` | Agent session bundle |

## The `vigolium storage` command

All subcommands operate on the active project. Every subcommand fails with a clear error if storage is disabled.

```bash
vigolium storage ls                              # list all objects in the project
vigolium storage ls --prefix ugc/                # filter by prefix
vigolium storage ls --tree                       # render as a directory tree
vigolium storage ls --json

vigolium storage upload ./bundle.tar.gz                         # → ugc/bundle.tar.gz
vigolium storage upload ./bundle.tar.gz --key imports/manual.tar.gz
vigolium storage upload ./bundle.tar.gz --content-type application/gzip

vigolium storage download <key>                  # writes to stdout by default
vigolium storage download ugc/bundle.tar.gz -o ./local.tar.gz
vigolium storage get ...                         # alias for download

vigolium storage results <scan-uuid>             # downloads the scan's result bundle
vigolium storage results <run-uuid>  -o ./run.tar.gz

vigolium storage presign --key ugc/foo.tar.gz                    # default: GET, 1h
vigolium storage presign --key uploads/incoming.tar.gz --method PUT --expiry 30m
vigolium storage presign --key ugc/foo.tar.gz --json

vigolium storage rm imports/old.tar.gz                            # prompts for confirmation
vigolium storage rm imports/a.tar.gz imports/b.tar.gz -F          # batch + force
vigolium storage delete ...                       # alias for rm
```

`ls` and `rm` accept their `list` / `delete` aliases. `download` accepts `get`.

## Storage-aware import / export

### Import from storage

```bash
vigolium import gs://<project-uuid>/imports/litellm-archon.tar.gz
```

`vigolium import` accepts `gs://` URLs as the input argument. The flow:

1. Download the object to a temp file.
2. If it's a `.tar.gz` / `.tgz` / `.zip`, extract it to a temp dir; otherwise treat as JSONL.
3. Detect archon folders (`audit-state.json`) or JSONL envelopes and run the matching importer.
4. For archon imports, copy the resolved folder verbatim into `~/.vigolium/agent-sessions/<run-uuid>/archon/` and stamp `session_dir` and `storage_url` (the original `gs://` URL) on the agentic_scan row.
5. Clean up the temp dir.

### Push the import source up after importing

```bash
vigolium import ./local-archon-folder --upload                # default key: imports/<base>-<ts>.tar.gz
vigolium import ./local-archon-folder --upload-key imports/manual.zip   # zip instead
```

`--upload` bundles the local folder to `.tar.gz` (or `.zip` if `--upload-key` ends in `.zip`) and uploads it. Single files are uploaded as-is. `--upload-key` implies `--upload`. The flag is silently ignored if the input was already a `gs://` URL.

### Export to storage

Any export format can target a `gs://` URL via `-o`:

```bash
vigolium export --format jsonl    -o gs://{project-uuid}/exports/data-{ts}.jsonl
vigolium export --format html     -o gs://{project-uuid}/exports/report-{ts}.html
vigolium export --format pdf      -o gs://{project-uuid}/exports/report-{ts}.pdf
vigolium export --format markdown -o gs://{project-uuid}/exports/report-{ts}.md
vigolium export --format bundle   -o gs://{project-uuid}/exports/bundle-{ts}.tar.gz \
                                    --scan-uuid <run-uuid>
```

Vigolium writes to a temp file locally, then uploads on success. If the upload fails, the export is reported as failed (the temp file is cleaned up regardless).

### Bundle export

The `bundle` format (alias `gz`) emits a single `.tar.gz` containing JSONL data, an HTML report, a manifest, and any agent session directories named with `--scan-uuid`:

```
<basename>/
  manifest.json
  export.jsonl
  report.html
  sessions/<uuid>/...    # verbatim copy of ~/.vigolium/agent-sessions/<uuid>/
```

`--scan-uuid <uuid>` is repeatable. Each value is an `agentic_scans` row UUID; the bundle pulls in the matching `~/.vigolium/agent-sessions/<uuid>/` directory. Missing or unknown UUIDs are warned-and-skipped, so the bundle still ships even if a session dir was pruned. When exactly one `--scan-uuid` is given and resolves to an `agentic_scans` row, the HTML report's target and duration are auto-filled from that row. CLI `--report-target` / `--report-duration` flags still take precedence.

`-o` is required and must end in `.tar.gz` or `.tgz`. The top-level directory name inside the tarball is the basename of `-o` minus the archive extension.

## Auto-uploading scan results

Native scan:

```bash
vigolium scan https://target.com --upload-results
# → uploads native-scans/<scan-uuid>/results.tar.gz and stamps storage_url on the scan row
```

Agent runs:

```bash
vigolium agent autopilot --input req.txt           --upload-results
vigolium agent swarm     --input req.txt --discover --upload-results
vigolium agent archon    --source ./repo --upload-results
# → uploads agentic-scans/<run-uuid>/results.tar.gz and stamps storage_url on the agentic_scan row
```

Both flags require storage to be enabled; they emit a warning and skip the upload otherwise (the scan or run still completes locally). The bundle includes the session directory plus, for native scans, the configured output formats and `runtime.log` when `persist_logs` is on.

## Round-tripping a bundle

Because `vigolium import` understands tar.gz / zip archives and detects nested archon folders or JSONL files within them, you can ship a `bundle` export to another machine and re-import it:

```bash
# machine A
vigolium export --format bundle -o /tmp/snapshot.tar.gz --scan-uuid <run-uuid>
vigolium storage upload /tmp/snapshot.tar.gz --key snapshots/snapshot.tar.gz

# machine B
vigolium import gs://<project-uuid>/snapshots/snapshot.tar.gz
```

Caveat: an imported bundle currently re-creates a new `agentic_scans` row from the embedded archon folder while the embedded `export.jsonl` re-imports the findings. The findings are de-duplicated, but the agentic_scan row is fresh — the new row will reference the same source data but won't share its UUID with the original.

## Security notes

- **Project isolation.** All keys are validated and prefixed with the project UUID server-side; clients cannot read or write objects outside their project.
- **Path traversal.** Keys containing `..`, `\`, or absolute paths are rejected by `storage.ValidateKey` before any backend call.
- **Presigned URLs** are bounded by `--expiry` (default 1h). They inherit the project prefix; they cannot be used to reach outside the project.
- **Credentials live in config.** Use `${ENV_VAR}` interpolation in `vigolium-configs.yaml` rather than committing keys; the loader expands env vars at config-load time.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `cloud storage is not enabled` | `storage.enabled` is false (or `VIGOLIUM_STORAGE_ENABLED=false`) | Set `storage.enabled: true` or `VIGOLIUM_STORAGE_ENABLED=true` |
| `storage.bucket must not be empty` | Bucket missing in config | Set `storage.bucket` in YAML |
| `storage.endpoint is required when driver is minio` | MinIO needs an explicit endpoint | Set `storage.endpoint: minio.example.com:9000` |
| `path contains traversal or invalid characters` | Key contains `..`, `\`, or escapes its project | Use a clean relative key like `exports/foo.html` |
| `Storage URL project (X) differs from active project (Y)` | `gs://` URL refers to a different project | Either `vigolium project use <X>` or accept the cross-project copy |
| `failed to upload to gs://...` after a successful export | Network or credential issue at upload time | Re-run; check bucket permissions, IAM/HMAC key validity |
| `--upload-results specified but storage is not enabled` (warning, scan still completes) | Upload skipped at runtime | Enable storage, or drop the flag |

## Related

- [Configuration reference](configuration.md) — full YAML layout including the `storage:` block
- [Projects and multi-tenancy](projects.md) — how project UUIDs scope storage access
- [Output and reporting](output-and-reporting.md) — `--format` options and report metadata
- [Server mode](server-mode/) — REST API endpoints under `/api/storage/`
