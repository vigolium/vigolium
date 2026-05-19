# Vigolium API Reference — Generic Database API

Unified CRUD API for interacting with any database table. Returns raw JSON and supports pagination, filtering, sorting, column selection, and full-text search across all tables.

Read endpoints (GET) require **viewer** role or above. Write endpoints (POST, PUT, DELETE) require **admin** role.

Project-scoped tables (`scans`, `http_records`, `findings`, `source_repos`, `session_hostnames`, `oast_interactions`, `scan_logs`, `agentic_scans`, `scopes`) automatically filter by the `X-Project-UUID` header. Pass `?all_projects=true` to disable project scoping (admin use).

---

## GET /api/db/tables — List All Tables

Returns all database tables with their row counts.

```bash
curl -s http://localhost:9002/api/db/tables | jq .
```

```json
{
  "tables": [
    { "name": "agentic_scans", "row_count": 42 },
    { "name": "findings", "row_count": 1567 },
    { "name": "http_records", "row_count": 24301 },
    { "name": "scans", "row_count": 15 },
    { "name": "source_repos", "row_count": 3 }
  ],
  "total": 12
}
```

---

## GET /api/db/tables/:table/columns — List Table Columns

Returns column metadata and primary key information for a specific table.

```bash
# Get columns for the findings table
curl -s http://localhost:9002/api/db/tables/findings/columns | jq .
```

```json
{
  "table": "findings",
  "columns": [
    { "name": "id", "type": "INTEGER", "nullable": "no" },
    { "name": "project_uuid", "type": "TEXT", "nullable": "no" },
    { "name": "module_id", "type": "TEXT", "nullable": "yes" },
    { "name": "severity", "type": "TEXT", "nullable": "yes" },
    { "name": "created_at", "type": "DATETIME", "nullable": "no" }
  ],
  "primary_key": ["id"],
  "total": 22
}
```

**Error responses:**

| Code | Condition                        |
|------|----------------------------------|
| 404  | Table name not found in database |

---

## GET /api/db/tables/:table/records — List Records

Returns paginated, filtered, sorted records from any table.

**Query parameters:**

| Parameter              | Type   | Default | Description                                                    |
|------------------------|--------|---------|----------------------------------------------------------------|
| `limit`                | int    | 100     | Number of records to return (max 1000)                         |
| `offset`               | int    | 0       | Offset for pagination                                          |
| `sort`                 | string |         | Column name to sort by (validated against table schema)        |
| `order`                | string | `desc`  | Sort order: `asc` or `desc`                                   |
| `columns`              | string |         | Comma-separated column whitelist (only return these columns)   |
| `search`               | string |         | Fuzzy search across all text/varchar columns                   |
| `truncate`             | int    | 0       | Truncate large text/binary fields to N characters (0 = full)   |
| `all_projects`         | string | `false` | Set to `true` to disable automatic project_uuid filtering      |
| `filter.<column>`      | string |         | Exact match filter on a column                                 |
| `filter.<column>__like`| string |         | SQL LIKE pattern match (`%` wildcards)                         |
| `filter.<column>__gt`  | string |         | Greater than comparison                                        |
| `filter.<column>__gte` | string |         | Greater than or equal comparison                                |
| `filter.<column>__lt`  | string |         | Less than comparison                                           |
| `filter.<column>__lte` | string |         | Less than or equal comparison                                  |
| `filter.<column>__in`  | string |         | Comma-separated IN list                                        |
| `filter.<column>__neq` | string |         | Not equal comparison                                           |

```bash
# List HTTP records with default pagination
curl -s http://localhost:9002/api/db/tables/http_records/records | jq .

# Filter findings by severity
curl -s 'http://localhost:9002/api/db/tables/findings/records?filter.severity__in=critical,high' | jq .

# Search across text fields
curl -s 'http://localhost:9002/api/db/tables/http_records/records?search=example.com' | jq .

# Select specific columns only
curl -s 'http://localhost:9002/api/db/tables/http_records/records?columns=uuid,hostname,method,path,status_code' | jq .

# Sort by response time, ascending
curl -s 'http://localhost:9002/api/db/tables/http_records/records?sort=response_time_ms&order=asc' | jq .

# Combine filters: GET requests with status > 399
curl -s 'http://localhost:9002/api/db/tables/http_records/records?filter.method=GET&filter.status_code__gt=399' | jq .

# LIKE filter with wildcards
curl -s 'http://localhost:9002/api/db/tables/http_records/records?filter.hostname__like=%25example%25' | jq .

# Paginate through results
curl -s 'http://localhost:9002/api/db/tables/http_records/records?limit=50&offset=100' | jq .

# Truncate large fields for listing views
curl -s 'http://localhost:9002/api/db/tables/http_records/records?truncate=200' | jq .

# List all agent runs across all projects
curl -s 'http://localhost:9002/api/db/tables/agentic_scans/records?all_projects=true' | jq .

# List scan logs for a specific scan
curl -s 'http://localhost:9002/api/db/tables/scan_logs/records?filter.scan_uuid=abc-123&sort=created_at&order=asc' | jq .
```

```json
{
  "table": "http_records",
  "total": 4521,
  "limit": 100,
  "offset": 0,
  "columns": ["uuid", "hostname", "method", "path", "status_code", "..."],
  "records": [
    {
      "uuid": "rec-0001-aaaa-bbbb-cccc",
      "hostname": "example.com",
      "method": "GET",
      "path": "/api/users",
      "status_code": 200
    }
  ]
}
```

**Error responses:**

| Code | Condition                              |
|------|----------------------------------------|
| 400  | Invalid query parameter or filter      |
| 404  | Table not found                        |

---

## GET /api/db/tables/:table/records/:id — Get Single Record

Returns a single record by its primary key value. Only works for tables with a single-column primary key.

```bash
# Get a specific HTTP record by UUID
curl -s http://localhost:9002/api/db/tables/http_records/records/rec-0001-aaaa-bbbb-cccc | jq .

# Get a specific finding by ID
curl -s http://localhost:9002/api/db/tables/findings/records/42 | jq .
```

```json
{
  "table": "findings",
  "record": {
    "id": 42,
    "project_uuid": "00000000-0000-0000-0000-000000000001",
    "module_id": "xss-reflected",
    "module_name": "Reflected XSS",
    "severity": "high",
    "confidence": "confirmed",
    "matched_at": "https://example.com/search?q=test",
    "created_at": "2026-03-20T14:30:00Z"
  }
}
```

**Error responses:**

| Code | Condition                                              |
|------|--------------------------------------------------------|
| 400  | Table not found or composite PK (not supported)       |
| 404  | Record not found                                       |

---

## POST /api/db/tables/:table/records — Create Record

Inserts a new record into the specified table. Requires **admin** role.

The request body is a JSON object where keys are column names and values are the data to insert. Column names are validated against the table schema. For project-scoped tables, `project_uuid` is automatically injected from the `X-Project-UUID` header if not provided in the body.

```bash
# Create a scope rule
curl -s -X POST http://localhost:9002/api/db/tables/scopes/records \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "include-example",
    "rule_type": "include",
    "host_pattern": "*.example.com",
    "enabled": true
  }' | jq .
```

```json
{
  "table": "scopes",
  "message": "record created"
}
```

**Error responses:**

| Code | Condition                                    |
|------|----------------------------------------------|
| 400  | Invalid JSON, invalid column name, or empty fields |
| 500  | Database constraint violation                |

---

## PUT /api/db/tables/:table/records/:id — Update Record

Updates one or more fields on an existing record. Requires **admin** role.

Only the fields included in the request body are updated (partial update). Primary key columns cannot be updated. Column names are validated against the table schema.

```bash
# Update a finding's severity
curl -s -X PUT http://localhost:9002/api/db/tables/findings/records/42 \
  -H 'Content-Type: application/json' \
  -d '{"severity": "critical"}' | jq .

# Update an HTTP record's risk score and remarks
curl -s -X PUT http://localhost:9002/api/db/tables/http_records/records/rec-0001-aaaa-bbbb-cccc \
  -H 'Content-Type: application/json' \
  -d '{"risk_score": 85, "remarks": "manually verified"}' | jq .
```

```json
{
  "table": "findings",
  "id": "42",
  "message": "record updated"
}
```

**Error responses:**

| Code | Condition                                           |
|------|-----------------------------------------------------|
| 400  | Invalid JSON, invalid column, or attempt to update PK |
| 404  | Record not found                                    |

---

## DELETE /api/db/tables/:table/records/:id — Delete Record

Deletes a single record by primary key. Requires **admin** role.

```bash
# Delete a finding
curl -s -X DELETE http://localhost:9002/api/db/tables/findings/records/42 | jq .

# Delete a scan log entry
curl -s -X DELETE http://localhost:9002/api/db/tables/scan_logs/records/100 | jq .
```

```json
{
  "table": "findings",
  "id": "42",
  "message": "record deleted"
}
```

**Error responses:**

| Code | Condition          |
|------|--------------------|
| 404  | Record not found   |
| 500  | Database error     |
