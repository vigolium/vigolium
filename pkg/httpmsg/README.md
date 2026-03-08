# httpmsg - HTTP Request/Response Processing

HTTP request analysis library for security scanners. Provides request parsing, parameter extraction, and insertion point creation.

## Quick Commands

```bash
go test -v ./pkg/httpmsg/...           # Run all tests
go test -race ./pkg/httpmsg/...        # Test with race detector
go test -run TestInsertionPoint ./pkg/httpmsg/...  # Test insertion points
go test -run Example ./pkg/httpmsg/... # Run example tests
```

## Architecture

| Category | Files |
|----------|-------|
| Analysis | `request_analyzer.go`, `response_analyzer.go`, `request_info.go` |
| Parsers | `query_parser.go`, `json_parser.go`, `xml_parser.go`, `multipart_parser.go`, `urlencoded_parser.go`, `path_parser.go` |
| Insertion Points | `insertion_point.go` (interface), `insertion_point_impl.go` (3 implementations) |
| Request Building | `request_builder_*.go` (8 files, fluent API) |
| Models | `parameter.go`, `http_request.go`, `http_response.go`, `service.go` |
| Byte Utils | `byte_utils.go` (body offset, HTTP/2), `byte_search.go` (search/replace) |
| String Utils | `string_utils.go` (hex, filter, encoding) |

## Key Patterns

### 1. Byte Offset Tracking

Every `Parameter` stores exact byte positions in original request:

```go
param.NameStart, param.NameEnd     // Where name appears
param.ValueStart, param.ValueEnd   // Where value appears (for injection)
```

Critical for: payload offset calculation, response matching.

### 2. Three InsertionPoint Implementations

| Type | Use Case |
|------|----------|
| `ParameterInsertionPoint` | Standard params with auto-encoding per type |
| `EncodedInsertionPoint` | Custom encoder (Base64, double-URL, etc.) |
| `NestedInsertionPoint` | Multi-layer: JSON in URL param, Base64 wrapping |

### InsertionPointType Reference

| Type | Location | Encoding | Content-Length Update |
|------|----------|----------|----------------------|
| `INS_PARAM_URL` | Query string value (`?id=VALUE`) | URL encode | No |
| `INS_PARAM_BODY` | Form body value (`name=VALUE`) | URL encode | Yes |
| `INS_PARAM_COOKIE` | Cookie value (`Cookie: name=VALUE`) | URL encode | No |
| `INS_PARAM_JSON` | JSON value (`{"key":VALUE}`) | JSON escape | Yes |
| `INS_PARAM_XML` | XML element (`<tag>VALUE</tag>`) | Raw | Yes |
| `INS_PARAM_XML_ATTR` | XML attribute (`attr="VALUE"`) | Raw | Yes |
| `INS_PARAM_MULTIPART_ATTR` | Multipart attr (`filename="VALUE"`) | Raw | Yes |
| `INS_HEADER` | Header value (`Header: VALUE`) | Raw | No |
| `INS_URL_PATH_FOLDER` | URL path folder (`/api/VALUE/`) | URL encode | No |
| `INS_URL_PATH_FILENAME` | URL path filename (`/api/VALUE`) | URL encode | No |
| `INS_PARAM_NAME_URL` | Query param name (`?NAME=value`) | URL encode | No |
| `INS_PARAM_NAME_BODY` | Form param name (`NAME=value`) | URL encode | Yes |
| `INS_ENTIRE_BODY` | Entire body (replaces all) | Raw | Yes |

**Encoding details:**
- **URL encode**: `EncodeQueryValue()` - space→`+`, special chars→`%XX`
- **JSON escape**: Type-aware - strings get `\"` escaping, numbers/bools pass as-is
- **Raw**: No encoding applied

**Content-Length Update**: Call `UpdateContentLength()` after modifying body-affecting types.

### 3. Type-Aware Encoding

`BuildRequest(payload)` auto-encodes based on `InsertionPointType`:
- `INS_PARAM_URL` → URL encode
- `INS_PARAM_JSON` → JSON escape, preserve type (string/number/bool)
- `INS_PARAM_XML` → XML entity encode

### 4. Nested Parameter Discovery

`CreateAllInsertionPoints(request, true)` finds:
- JSON embedded in URL query params
- Base64 encoded data containing params
- XML in POST body

## API Selection Guide

| Goal | API |
|------|-----|
| Extract all parameters for analysis | `AnalyzeRequest()` → `RequestInfo.Parameters` |
| Build scanner with payload injection | `CreateAllInsertionPoints(req, includeNested)` |
| Modify request headers/params | `request_builder_*.go` functions |
| Parse specific body type | `ParseJSONBody()`, `ParseXMLBody()`, etc. |

**includeNested parameter:**
- `false` = faster, only direct parameters
- `true` = thorough, discovers nested structures

## Utility Functions

### Byte Operations (`byte_utils.go`, `byte_search.go`)
| Function | Description |
|----------|-------------|
| `FindBodyOffset(req)` | Find where HTTP body starts |
| `FindBodyEnd(req, startOffset)` | Find where HTTP body ends (before trailing CRLF) |
| `IsHTTP2(req)` | Check if request uses HTTP/2 |
| `ConvertToHTTP1(req)` | Convert HTTP/2 to HTTP/1.1 |
| `GetHeaders(msg)` | Extract all headers as string |
| `GetHeadersBytes(msg)` | Extract all headers as bytes |
| `SliceBytes(data, start, end)` | Safe byte slicing with bounds checking |
| `IndexOfByte(data, target, startOffset)` | Find first occurrence of a single byte |
| `IndexOfBytes(data, target, startOffset)` | Find first occurrence of a byte sequence |
| `ContainsBytes(data, pattern)` | Check if data contains pattern |
| `CountMatches(data, pattern)` | Count pattern occurrences |
| `GetMatches(data, pattern, limit)` | Get all [start, end] positions |

### Response Analysis (`response_analyzer.go`)
| Function | Description |
|----------|-------------|
| `AnalyzeResponse(resp)` | Full response parsing → `*ResponseInfo` |
| `IsResponse(msg)` | Check if message is HTTP response |
| `IsRequest(msg)` | Check if message is HTTP request |
| `GetStatusCode(resp)` | Extract status code from response |
| `GetStartType(resp)` | Detect content type from body start |
| `GetNestedResponse(resp)` | Extract nested HTTP response from body |

**Types:**
- `ResponseInfo` - Parsed response: StatusCode, Headers, BodyOffset, StatedMimeType, InferredMimeType, Cookies
- `Cookie` - HTTP cookie: Name, Value, Domain, Path, Expiration

### String Utils (`string_utils.go`)
| Function | Description |
|----------|-------------|
| `BytesToHexString(data)` | Convert bytes to space-separated hex |
| `FilterString(input, safeChars)` | Keep only allowed characters |
| `EncodeBytesAbove7F(input)` | URL-encode bytes > 0x7F |

## Gotchas

1. **Content-Length auto-update**: `InsertionPoint.BuildRequest()` does NOT update Content-Length. Use `UpdateContentLength()` after body modifications.

2. **JSON type preservation**: When injecting into JSON numbers/bools, payload must be valid JSON literal or it breaks parsing. Use `JSONValueType` field to check.

3. **Nested IP deduplication**: When `includeNested=true`, same logical injection point may appear multiple times with different encoding paths. Handle duplicates in scanner.

4. **Offset invalidation**: After modifying request bytes, all `Parameter` offsets become invalid. Re-analyze if needed.

5. **Multipart boundary**: `ParseMultipartBody()` requires boundary from Content-Type header. Use `ExtractBoundary()` helper.

6. **Loop-based algorithms**: All byte operations use loop-based algorithms (no regex) following Burp patterns.

7. **Immutable pattern**: Utility functions return new slices, never modify input.

8. **FromStdRequest port preservation**: When converting `*http.Request` → `HttpRequestResponse`, always use `req.URL.Port()` and `req.URL.Hostname()` for service info. The intermediate `ParseRawRequest()` may lose port from Host header.
