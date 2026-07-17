# Vigolium API Reference — Stats

## GET /api/stats — Scan Statistics

Returns aggregated statistics about HTTP records, modules, and findings.

```bash
curl -s http://localhost:9002/api/stats | jq .
```

```json
{
  "project_uuid": "00000000-0000-0000-defa-c01001000001",
  "http_records": {
    "total": 1234
  },
  "modules": {
    "active": { "total": 201, "enabled": 201 },
    "passive": { "total": 116, "enabled": 116 }
  },
  "findings": {
    "total": 42,
    "by_severity": {
      "critical": 2,
      "high": 10,
      "medium": 15,
      "low": 10,
      "info": 5
    }
  }
}
```
