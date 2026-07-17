# Vigolium API Reference — Cloud Storage

## Overview

The storage API provides cloud object storage integration for source code upload/download and scan result archival. All objects are scoped to a project via the `X-Project-UUID` header and stored under `<bucket>/<project-uuid>/`.

Storage is **disabled by default**. Enable it by setting `storage.enabled: true` in `vigolium-configs.yaml`. All endpoints return `503 Service Unavailable` when storage is not configured.

| Endpoint                              | Method | Role     | Description                              |
|---------------------------------------|--------|----------|------------------------------------------|
| `/api/storage/upload-source`          | POST   | Operator | Upload source code archive               |
| `/api/storage/source/:key`            | GET    | Viewer   | Download source code by key              |
| `/api/storage/results/:scan-uuid`     | GET    | Viewer   | Download scan result bundle (.tar.gz)    |
| `/api/storage/presign`                | POST   | Operator | Generate presigned upload/download URL   |

---

## Security

All storage operations enforce project-level isolation:

- Every object path is prefixed with the authenticated project UUID (`<bucket>/<project-uuid>/<key>`). The project UUID comes from the `X-Project-UUID` header, set by server middleware — clients cannot override the prefix.
- Keys and UUIDs are validated against path traversal (`../`, `..\\`, `..`) before any storage operation. Malicious keys are rejected with `400 Bad Request`.
- Presigned URLs are scoped to the requesting project — a presigned URL for project A cannot access objects in project B.

---

## GCP Setup

Vigolium uses S3-compatible HMAC keys to talk to GCS. You need to create HMAC credentials from a service account, then configure them in `vigolium-configs.yaml`.

### Step 1: Create HMAC Keys from a Service Account

If you have a service account JSON key (e.g. `gcs-readwrite-key.json`), activate it and create HMAC credentials:

```bash
# Authenticate with the service account
gcloud auth activate-service-account --key-file=/path/to/gcs-readwrite-key.json

# Get the service account email from the key file
SA_EMAIL=$(jq -r '.client_email' /path/to/gcs-readwrite-key.json)

# Create HMAC keys for the service account
gcloud storage hmac create "$SA_EMAIL"
```

This outputs an `accessId` and `secret`. Save both — the secret is only shown once.

### Step 2: Create a GCS Bucket

```bash
# Create a bucket in your preferred region
gcloud storage buckets create gs://my-vigolium-bucket \
  --location=asia-southeast1 \
  --uniform-bucket-level-access

# Grant the service account read/write access
gcloud storage buckets add-iam-policy-binding gs://my-vigolium-bucket \
  --member="serviceAccount:$SA_EMAIL" \
  --role="roles/storage.objectAdmin"
```

### Step 3: Configure Vigolium

Set the credentials and bucket name as environment variables:

```bash
export VIGOLIUM_STORAGE_ACCESS_KEY="GOOG1E..."        # accessId from step 1
export VIGOLIUM_STORAGE_SECRET_KEY="abc123..."          # secret from step 1
export VIGOLIUM_STORAGE_BUCKET_NAME="my-vigolium-bucket"
```

Then configure `~/.vigolium/vigolium-configs.yaml`:

```yaml
storage:
  enabled: true
  driver: gcs
  bucket: ${VIGOLIUM_STORAGE_BUCKET_NAME}
  region: asia-southeast1
  access_key: ${VIGOLIUM_STORAGE_ACCESS_KEY}
  secret_key: ${VIGOLIUM_STORAGE_SECRET_KEY}
  use_ssl: true
```

### Step 4: Verify Connectivity

```bash
# Upload a test file
curl -s -X POST http://localhost:9002/api/storage/upload-source \
  -H "Authorization: Bearer <token>" \
  -H "X-Project-UUID: my-project-uuid" \
  -F "file=@test-source.tar.gz" | jq .

# Generate a presigned download URL
curl -s -X POST http://localhost:9002/api/storage/presign \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -H "X-Project-UUID: my-project-uuid" \
  -d '{"key": "ugc/test-source.tar.gz", "method": "GET"}' | jq .url
```

### AWS S3 / MinIO

For AWS S3, change the driver and region:

```yaml
storage:
  enabled: true
  driver: s3
  bucket: ${VIGOLIUM_STORAGE_BUCKET_NAME}
  region: us-east-1
  access_key: ${AWS_ACCESS_KEY_ID}
  secret_key: ${AWS_SECRET_ACCESS_KEY}
```

For self-hosted MinIO, set the endpoint explicitly:

```yaml
storage:
  enabled: true
  driver: minio
  endpoint: minio.internal:9000
  bucket: ${VIGOLIUM_STORAGE_BUCKET_NAME}
  access_key: ${MINIO_ACCESS_KEY}
  secret_key: ${MINIO_SECRET_KEY}
  use_ssl: false
  path_style: true
```

---

## Storage Object Layout

All objects are prefixed with the project UUID for multi-tenant isolation:

```
<bucket>/
  <project-uuid>/
    ugc/                              # User-uploaded source code
      source-code.tar.gz
      my-app.zip
    native-scans/                     # Native scan result bundles
      <scan-uuid>/
        results.tar.gz                # Bundled findings JSONL, HTML report, stats
    agentic-scans/                    # Agentic scan result bundles
      <agentic-scan-uuid>/
        results.tar.gz                # Bundled session dir (output.md, extensions/, plan.json)
```

Result bundles use `.tar.gz` format (gzip-compressed tar), matching the `vigolium db export --format bundle` format.

---

## CLI Usage

### Source Download from Storage

Agent source-aware commands accept `gs://` URIs and download/extract the
archive before running:

```bash
# Agentic swarm with source from GCS
vigolium agent swarm -t https://example.com \
  --source gs://<project-uuid>/ugc/source-code.tar.gz

# Autopilot with source from GCS
vigolium agent autopilot -t https://example.com \
  --source gs://<project-uuid>/ugc/source-code.tar.gz
```

The archive is downloaded, extracted to a temp directory, and cleaned up after the scan completes. The `source_type` field in the DB records `"gcs"`.

### Result Upload to Storage

Add `--upload-results` to upload scan results to cloud storage after completion:

```bash
# Native scan — upload findings JSONL + HTML report as tar.gz bundle
vigolium scan -t https://example.com -o results --format jsonl,html --upload-results

# Agentic swarm — upload session dir as tar.gz bundle
vigolium agent swarm -t https://example.com --upload-results

# Autopilot — upload session artifacts as tar.gz bundle
vigolium agent autopilot -t https://example.com --source ./src --upload-results
```

Results are uploaded to:
- **Native scans:** `gs://<project-uuid>/native-scans/<scan-uuid>/results.tar.gz`
- **Agentic scans:** `gs://<project-uuid>/agentic-scans/<run-uuid>/results.tar.gz`

The `storage_url` field on the Scan / AgenticScan DB record is updated with the `gs://` URL after upload.

---

## POST /api/storage/upload-source

Uploads a source code archive to cloud storage, scoped to the project.

**Content-Type:** `multipart/form-data`

| Field  | Type | Required | Description                  |
|--------|------|----------|------------------------------|
| `file` | file | Yes      | Source code archive to upload |

```bash
curl -s -X POST http://localhost:9002/api/storage/upload-source \
  -H "Authorization: Bearer <token>" \
  -H "X-Project-UUID: my-project-uuid" \
  -F "file=@source-code.tar.gz" | jq .
```

**Response (200):**

```json
{
  "storage_url": "gs://my-project-uuid/ugc/source-code.tar.gz",
  "key": "ugc/source-code.tar.gz",
  "filename": "source-code.tar.gz",
  "size": 1048576,
  "message": "source uploaded successfully"
}
```

The returned `storage_url` can be passed to `--source` on `agent swarm`,
`agent autopilot`, or `agent audit`, or to the corresponding agent API
`source` field. Native `vigolium scan` has no source-code flag.

---

## GET /api/storage/source/:key

Downloads a previously uploaded source file.

```bash
curl -s -o source.tar.gz \
  http://localhost:9002/api/storage/source/source-code.tar.gz \
  -H "Authorization: Bearer <token>" \
  -H "X-Project-UUID: my-project-uuid"
```

Returns the file as `application/octet-stream` with `Content-Disposition: attachment`.

Returns `400` if the key contains path traversal sequences.

---

## GET /api/storage/results/:scan-uuid

Downloads the result bundle for a native scan or agentic scan. Searches `native-scans/<uuid>/results.tar.gz` first, then `agentic-scans/<uuid>/results.tar.gz`.

```bash
curl -s -o results.tar.gz \
  http://localhost:9002/api/storage/results/550e8400-e29b-41d4-a716-446655440000 \
  -H "Authorization: Bearer <token>" \
  -H "X-Project-UUID: my-project-uuid"
```

Returns `application/gzip` with `Content-Disposition: attachment`.

Returns `404` if no results have been uploaded for the given UUID.

Extract the bundle:

```bash
tar xzf results.tar.gz
```

---

## POST /api/storage/presign

Generates a presigned URL for direct upload or download, bypassing the API server. Useful for large files or client-side uploads.

**Request body:**

| Field           | Type   | Required | Description                                       |
|-----------------|--------|----------|---------------------------------------------------|
| `key`           | string | Yes      | Object key (e.g. `ugc/source-code.tar.gz`)        |
| `method`        | string | No       | `GET` (default) or `PUT`                          |
| `expiry_seconds`| int    | No       | URL expiry in seconds (default: `3600` / 1 hour)  |

```bash
# Generate a download URL
curl -s -X POST http://localhost:9002/api/storage/presign \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -H "X-Project-UUID: my-project-uuid" \
  -d '{
    "key": "ugc/source-code.tar.gz",
    "method": "GET",
    "expiry_seconds": 3600
  }' | jq .

# Generate an upload URL (for client-side direct upload)
curl -s -X POST http://localhost:9002/api/storage/presign \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -H "X-Project-UUID: my-project-uuid" \
  -d '{
    "key": "ugc/my-app.tar.gz",
    "method": "PUT"
  }' | jq .
```

**Response (200):**

```json
{
  "url": "https://storage.googleapis.com/my-bucket/my-project-uuid/ugc/source-code.tar.gz?X-Goog-Algorithm=...",
  "key": "ugc/source-code.tar.gz",
  "method": "GET",
  "expiry_seconds": 3600
}
```

Keys are validated against path traversal — requests with `../` or similar sequences are rejected with `400`.

---

## Using Storage with Agentic Scans (API)

### Upload Source, Then Run Agentic Scan

```bash
# 1. Upload source code
STORAGE_URL=$(curl -s -X POST http://localhost:9002/api/storage/upload-source \
  -H "Authorization: Bearer <token>" \
  -H "X-Project-UUID: my-project-uuid" \
  -F "file=@my-app.tar.gz" | jq -r '.storage_url')

echo "Uploaded to: $STORAGE_URL"

# 2. Run swarm with uploaded source + result upload
curl -s -X POST http://localhost:9002/api/agent/run/swarm \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -H "X-Project-UUID: my-project-uuid" \
  -d "{
    \"input\": \"https://example.com/api/users?id=1\",
    \"source\": \"$STORAGE_URL\",
    \"upload_results\": true,
    \"triage\": true
  }" | jq .

# 3. After scan completes, download and extract results
curl -s -o results.tar.gz \
  http://localhost:9002/api/storage/results/<run-id> \
  -H "Authorization: Bearer <token>" \
  -H "X-Project-UUID: my-project-uuid"

tar xzf results.tar.gz
```

### Run Autopilot with Local Source + Upload Results

```bash
curl -s -X POST http://localhost:9002/api/agent/run/autopilot \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -H "X-Project-UUID: my-project-uuid" \
  -d '{
    "target": "http://localhost:3000",
    "source": "/home/user/src/my-app",
    "upload_results": true,
    "intensity": "balanced"
  }' | jq .
```

### Run Swarm with GCS Source

```bash
curl -s -X POST http://localhost:9002/api/agent/run/swarm \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -H "X-Project-UUID: my-project-uuid" \
  -d '{
    "input": "https://example.com",
    "source": "gs://my-project-uuid/ugc/source-code.tar.gz",
    "upload_results": true,
    "code_audit": true,
    "triage": true
  }' | jq .
```

---

## Storage URL in Scan Records

When `upload_results` is enabled, the `storage_url` field is populated on the Scan or AgenticScan record after upload completes.

**Native scan:**

```bash
curl -s http://localhost:9002/api/scans/<scan-uuid> \
  -H "Authorization: Bearer <token>" | jq '.storage_url'
# "gs://my-project-uuid/native-scans/<scan-uuid>/results.tar.gz"
```

**Agentic scan:**

```bash
curl -s http://localhost:9002/api/agent/sessions/<run-id> \
  -H "Authorization: Bearer <token>" | jq '.storage_url'
# "gs://my-project-uuid/agentic-scans/<run-id>/results.tar.gz"
```
