# Vigolium API Reference — Stats

## GET /api/stats — Scan Statistics

Returns aggregated statistics about HTTP records, modules, and findings.

```bash
curl -s http://localhost:9002/api/stats | jq .
```

```json
{
  "http_records": {
    "total": 1234
  },
  "modules": {
    "active": { "total": 18, "enabled": 15 },
    "passive": { "total": 4, "enabled": 4 }
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
