# Vigolium API Reference — Cloud Storage

## Overview

The storage API provides cloud object storage integration for source code upload/download and scan result archival. All objects are scoped to a project via the `X-Project-UUID` header and stored under `<bucket>/<project-uuid>/`.

| Endpoint                              | Method | Role     | Description                              |
|---------------------------------------|--------|----------|------------------------------------------|
| `/api/storage/upload-source`          | POST   | Operator | Upload source code archive               |
| `/api/storage/source/:key`            | GET    | Viewer   | Download source code by key              |
| `/api/storage/results/:scan-uuid`     | GET    | Viewer   | Download scan result bundle              |
| `/api/storage/presign`                | POST   | Operator | Generate presigned upload/download URL   |

**Requires:** `storage.enabled: true` in `vigolium-configs.yaml`. All endpoints return `503 Service Unavailable` when storage is not configured.

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
gcloud storage buckets create gs://vigolium-data \
  --location=asia-southeast1 \
  --uniform-bucket-level-access

# Verify the service account has read/write access
gcloud storage buckets add-iam-policy-binding gs://vigolium-data \
  --member="serviceAccount:$SA_EMAIL" \
  --role="roles/storage.objectAdmin"
```

### Step 3: Configure Vigolium

Set the HMAC credentials as environment variables (recommended):

```bash
export VIGOLIUM_STORAGE_ACCESS_KEY="GOOG1E..."   # accessId from step 1
export VIGOLIUM_STORAGE_SECRET_KEY="abc123..."     # secret from step 1
```

Then configure `~/.vigolium/vigolium-configs.yaml`:

```yaml
storage:
  enabled: true
  driver: gcs
  bucket: vigolium-data
  region: asia-southeast1
  access_key: ${VIGOLIUM_STORAGE_ACCESS_KEY}
  secret_key: ${VIGOLIUM_STORAGE_SECRET_KEY}
  use_ssl: true
```

### Verify Connectivity

```bash
# Upload a test file via the API
curl -s -X POST http://localhost:9002/api/storage/upload-source \
  -H "Authorization: Bearer <token>" \
  -H "X-Project-UUID: my-project-uuid" \
  -F "file=@test.zip" | jq .

# Or generate a presigned URL
curl -s -X POST http://localhost:9002/api/storage/presign \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -H "X-Project-UUID: my-project-uuid" \
  -d '{"key": "ugc/test.zip", "method": "GET"}' | jq .url
```

---

## Storage Object Layout

All objects are prefixed with the project UUID for multi-tenant isolation:

```
<bucket>/
  <project-uuid>/
    ugc/                          # User-uploaded source code
      source-code.zip
      my-app.tar.gz
    native-scans/                 # Native scan results
      <scan-uuid>/
        results.zip               # Bundled findings JSONL, HTML report
    agentic-scans/                # Agentic scan results
      <agentic-scan-uuid>/
        results.zip               # Bundled session dir (output.md, extensions/, plan.json)
```

---

## CLI Usage

### Source Download from Storage

Use `gs://` URIs with `--source` to download source code from cloud storage before scanning:

```bash
# Native scan with source from GCS
vigolium scan -t https://example.com \
  --source gs://<project-uuid>/ugc/source-code.zip

# Agentic swarm with source from GCS
vigolium agent swarm -t https://example.com \
  --source gs://<project-uuid>/ugc/source-code.zip

# Autopilot with source from GCS
vigolium agent autopilot -t https://example.com \
  --source gs://<project-uuid>/ugc/source-code.zip
```

The scanner downloads the zip, extracts it to a temp directory, and scans against the extracted source. The `source_type` field in the DB records `"gcs"`.

### Result Upload to Storage

Add `--upload-results` to upload scan results to cloud storage after completion:

```bash
# Native scan — upload findings JSONL + HTML report
vigolium scan -t https://example.com -o results --format jsonl,html --upload-results

# Agentic swarm — upload session dir (output.md, extensions/, plan.json)
vigolium agent swarm -t https://example.com --upload-results

# Autopilot — upload session artifacts
vigolium agent autopilot -t https://example.com --source ./src --upload-results
```

Results are uploaded to:
- **Native scans:** `gs://<project-uuid>/native-scans/<scan-uuid>/results.zip`
- **Agentic scans:** `gs://<project-uuid>/agentic-scans/<run-uuid>/results.zip`

The `storage_url` field on the Scan / AgenticScan DB record is updated with the gs:// URL.

---

## POST /api/storage/upload-source — Upload Source Code

Uploads a source code archive to cloud storage, scoped to the project.

**Content-Type:** `multipart/form-data`

| Field  | Type | Required | Description                  |
|--------|------|----------|------------------------------|
| `file` | file | Yes      | Source code archive to upload |

```bash
curl -s -X POST http://localhost:9002/api/storage/upload-source \
  -H "Authorization: Bearer <token>" \
  -H "X-Project-UUID: my-project-uuid" \
  -F "file=@source-code.zip" | jq .
```

**Response (200):**

```json
{
  "storage_url": "gs://my-project-uuid/ugc/source-code.zip",
  "key": "ugc/source-code.zip",
  "filename": "source-code.zip",
  "size": 1048576,
  "message": "source uploaded successfully"
}
```

The returned `storage_url` can be used directly as the `--source` flag or `source` API field.

---

## GET /api/storage/source/:key — Download Source Code

Downloads a previously uploaded source file.

```bash
curl -s -o source.zip http://localhost:9002/api/storage/source/source-code.zip \
  -H "Authorization: Bearer <token>" \
  -H "X-Project-UUID: my-project-uuid"
```

Returns the file as `application/octet-stream` with `Content-Disposition: attachment`.

---

## GET /api/storage/results/:scan-uuid — Download Scan Results

Downloads the result bundle for a native scan or agentic scan. Searches `native-scans/<uuid>/results.zip` first, then `agentic-scans/<uuid>/results.zip`.

```bash
# Download native scan results
curl -s -o results.zip \
  http://localhost:9002/api/storage/results/550e8400-e29b-41d4-a716-446655440000 \
  -H "Authorization: Bearer <token>" \
  -H "X-Project-UUID: my-project-uuid"
```

Returns `404` if no results have been uploaded for the given UUID.

---

## POST /api/storage/presign — Generate Presigned URL

Generates a presigned URL for direct upload or download, bypassing the API server. Useful for large files or client-side uploads.

**Request body:**

| Field           | Type   | Required | Description                                       |
|-----------------|--------|----------|---------------------------------------------------|
| `key`           | string | Yes      | Object key (e.g. `ugc/source-code.zip`)           |
| `method`        | string | No       | `GET` (default) or `PUT`                          |
| `expiry_seconds`| int    | No       | URL expiry in seconds (default: `3600` / 1 hour)  |

```bash
# Generate a download URL
curl -s -X POST http://localhost:9002/api/storage/presign \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -H "X-Project-UUID: my-project-uuid" \
  -d '{
    "key": "ugc/source-code.zip",
    "method": "GET",
    "expiry_seconds": 3600
  }' | jq .

# Generate an upload URL (for client-side direct upload)
curl -s -X POST http://localhost:9002/api/storage/presign \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -H "X-Project-UUID: my-project-uuid" \
  -d '{
    "key": "ugc/my-app.zip",
    "method": "PUT"
  }' | jq .
```

**Response (200):**

```json
{
  "url": "https://storage.googleapis.com/vigolium-data/my-project-uuid/ugc/source-code.zip?X-Goog-Algorithm=...",
  "key": "ugc/source-code.zip",
  "method": "GET",
  "expiry_seconds": 3600
}
```

---

## Using Storage with Agentic Scans (API)

### Upload Source, Then Run Agentic Scan

```bash
# 1. Upload source code
STORAGE_URL=$(curl -s -X POST http://localhost:9002/api/storage/upload-source \
  -H "Authorization: Bearer <token>" \
  -H "X-Project-UUID: my-project-uuid" \
  -F "file=@my-app.zip" | jq -r '.storage_url')

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

# 3. After scan completes, download results
curl -s -o results.zip \
  http://localhost:9002/api/storage/results/<run-id> \
  -H "Authorization: Bearer <token>" \
  -H "X-Project-UUID: my-project-uuid"
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
    "source": "gs://my-project-uuid/ugc/source-code.zip",
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
# "gs://my-project-uuid/native-scans/<scan-uuid>/results.zip"
```

**Agentic scan:**

```bash
curl -s http://localhost:9002/api/agent/sessions/<run-id> \
  -H "Authorization: Bearer <token>" | jq '.storage_url'
# "gs://my-project-uuid/agentic-scans/<run-id>/results.zip"
```
