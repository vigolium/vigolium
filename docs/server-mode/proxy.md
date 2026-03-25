# Transparent Proxy

## Overview

Vigolium's server mode includes a built-in transparent HTTP proxy that passively records all traffic flowing through it. This lets you point any HTTP-capable tool at Vigolium and have its traffic automatically ingested for scanning.

## Starting the Proxy

Start the server with `--ingest-proxy-port` to enable the transparent proxy alongside the REST API:

```bash
export VIGOLIUM_API_KEY=my-secret-key
vigolium server --ingest-proxy-port 9003
```

This starts two listeners:
- **REST API** on port `9002` (default)
- **HTTP proxy** on port `9003`

## How It Works

The proxy sits between your tools and the target. All HTTP traffic passing through is automatically recorded in the database as HTTP records, ready for scanning.

HTTPS CONNECT tunneling is passed through without recording -- the proxy cannot inspect encrypted traffic without acting as a MITM, so TLS tunnels are forwarded transparently.

## Usage Examples

### curl

```bash
curl -x http://localhost:9003 https://example.com/api/users
```

### httpx

```bash
echo "https://example.com" | httpx -proxy http://localhost:9003
```

### nuclei

```bash
nuclei -u https://example.com -proxy http://localhost:9003
```

### Browser

Configure your browser's HTTP proxy to `localhost:9003`. In most browsers this is under network or proxy settings. For Firefox, go to Settings > Network Settings > Manual proxy configuration and set the HTTP Proxy to `localhost` with port `9003`.

## Querying Ingested Data

After routing traffic through the proxy, use the REST API to inspect what was recorded and view any scan findings.

### List HTTP Records

```bash
# All records (paginated, default limit=50)
curl -s http://localhost:9002/api/http-records \
  -H "Authorization: Bearer my-secret-key" | jq .

# Filter by domain
curl -s "http://localhost:9002/api/http-records?domain=example.com" \
  -H "Authorization: Bearer my-secret-key" | jq .

# Filter by status code and method
curl -s "http://localhost:9002/api/http-records?status_code=200,302&method=GET,POST" \
  -H "Authorization: Bearer my-secret-key" | jq .

# Search across URLs and headers
curl -s "http://localhost:9002/api/http-records?search=admin&limit=10" \
  -H "Authorization: Bearer my-secret-key" | jq .

# Pagination
curl -s "http://localhost:9002/api/http-records?limit=20&offset=40" \
  -H "Authorization: Bearer my-secret-key" | jq .
```

### List Findings

```bash
# All findings
curl -s http://localhost:9002/api/findings \
  -H "Authorization: Bearer my-secret-key" | jq .

# Filter by severity
curl -s "http://localhost:9002/api/findings?severity=high,critical" \
  -H "Authorization: Bearer my-secret-key" | jq .

# Filter by module
curl -s "http://localhost:9002/api/findings?module_name=xss-reflected" \
  -H "Authorization: Bearer my-secret-key" | jq .

# Filter by domain
curl -s "http://localhost:9002/api/findings?domain=example.com" \
  -H "Authorization: Bearer my-secret-key" | jq .
```

### Server Info

```bash
curl -s http://localhost:9002/server-info \
  -H "Authorization: Bearer my-secret-key" | jq .
```

Response:

```json
{
  "version": "0.1.0",
  "uptime": "2h15m30s",
  "service_addr": "0.0.0.0:9002",
  "proxy_addr": "0.0.0.0:9003",
  "db_driver": "sqlite",
  "queue_depth": 0,
  "total_records": 1542,
  "total_findings": 23
}
```
