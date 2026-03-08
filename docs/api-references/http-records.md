# Vigolium API Reference — HTTP Records

## GET /api/http-records — List HTTP Records

Returns paginated HTTP request/response records stored in the database. Response and request bodies are excluded from list responses for performance.

**Query parameters:**

| Parameter      | Type   | Default | Description                                  |
|----------------|--------|---------|----------------------------------------------|
| `limit`        | int    | 50      | Number of records to return (max 500)        |
| `offset`       | int    | 0       | Offset for pagination                        |
| `domain`       | string |         | Filter by hostname (supports `*` wildcards)  |
| `method`       | string |         | Filter by HTTP method (comma-separated)      |
| `path`         | string |         | Filter by path (supports `*` wildcards)      |
| `status_code`  | string |         | Filter by status code (comma-separated)      |
| `content_type` | string |         | Filter by response content type              |
| `search`       | string |         | Search across URL and path                   |
| `source`       | string |         | Filter by ingestion source (e.g. `ingest-server`, `cli`) |
| `min_risk`     | int    |         | Filter by minimum risk score                 |
| `remark`       | string |         | Filter by remark                             |
| `sort`         | string | `created_at` | Sort field: `created_at`, `sent_at`, `method`, `path`, `status_code`, `response_time` |
| `order`        | string | `desc`  | Sort order: `asc` or `desc`                  |

```bash
# List recent records
curl -s http://localhost:9002/api/http-records | jq .

# Filter by domain
curl -s 'http://localhost:9002/api/http-records?domain=example.com' | jq .

# Filter by status code and method
curl -s 'http://localhost:9002/api/http-records?status_code=200,301&method=GET' | jq .

# Paginate
curl -s 'http://localhost:9002/api/http-records?limit=10&offset=20' | jq .

# Sort by response time descending
curl -s 'http://localhost:9002/api/http-records?sort=response_time&order=desc' | jq .

# Wildcard domain search
curl -s 'http://localhost:9002/api/http-records?domain=*.example.com' | jq .
```

```json
{
  "data": [
    {
      "uuid": "rec-0056-seed-aaaa-bbbb-cccc0038",
      "scheme": "https",
      "hostname": "example.com",
      "port": 443,
      "ip": "93.184.216.34",
      "method": "GET",
      "path": "/ws/notifications",
      "url": "https://example.com/ws/notifications",
      "http_version": "HTTP/1.1",
      "request_content_length": 0,
      "request_hash": "5eca33649eaa2c83a1cecfa1f039e465",
      "status_code": 101,
      "status_phrase": "Switching Protocols",
      "response_http_version": "HTTP/1.1",
      "response_content_length": 0,
      "response_hash": "c175cfa5a478d9b4320fff7b557ff80c",
      "response_time_ms": 5,
      "response_words": 0,
      "has_response": true,
      "sent_at": "2026-03-03T10:39:52.423708Z",
      "received_at": "2026-03-03T10:39:52.428708Z",
      "created_at": "2026-03-03T10:39:52.423708Z",
      "source": "seed",
      "risk_score": 0
    }
  ],
  "total": 1234,
  "limit": 50,
  "offset": 0,
  "has_more": true
}
```

> **Note:** The fields `raw_request`, `raw_response`, `request_body`, `response_body`, `request_headers`, and `response_headers` are excluded from list responses for performance. Use `GET /api/http-records/:uuid` to access the full record including headers and bodies. Fields with empty values (e.g. `request_content_type`, `parameters`, `remarks`) are omitted from the JSON response.

---

## GET /api/http-records/:uuid — Get HTTP Record Detail

Returns a single HTTP record by UUID, including full blob fields (`raw_request`, `raw_response`, `request_body`, `response_body`).

```bash
curl -s http://localhost:9002/api/http-records/abc-123 | jq .
```

```json
{
  "uuid": "abc-123",
  "scheme": "https",
  "hostname": "example.com",
  "port": 443,
  "method": "POST",
  "path": "/api/login",
  "url": "https://example.com/api/login",
  "status_code": 200,
  "raw_request": "POST /api/login HTTP/1.1\r\nHost: example.com\r\n...",
  "raw_response": "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n...",
  "request_body": "{\"user\":\"admin\",\"pass\":\"test\"}",
  "response_body": "{\"token\":\"eyJ...\"}",
  "created_at": "2026-02-16T15:00:00Z"
}
```

**Error responses:**

| Code | Condition            |
|------|----------------------|
| 400  | Missing UUID         |
| 404  | Record not found     |
| 503  | Database unavailable |

---

## DELETE /api/http-records/:uuid — Delete HTTP Record

Deletes a single HTTP record by UUID. Associated `finding_records` junction rows are also removed.

```bash
curl -s -X DELETE http://localhost:9002/api/http-records/550e8400-e29b-41d4-a716-446655440000 | jq .
```

**Response:**

```json
{
  "message": "HTTP record deleted",
  "uuid": "550e8400-e29b-41d4-a716-446655440000"
}
```

| Status | Description              |
|--------|--------------------------|
| 200    | Record deleted           |
| 404    | Record not found         |
| 503    | Database not configured  |
