# HTTP Client Infrastructure (Week 5)

Production-ready HTTP client implementation for Burp Suite Content Discovery.

## Overview

This package provides a complete HTTP client infrastructure with:
- Connection pooling with TLS verification disabled
- Middleware chain (retry, rate-limit) plus client-level request timeout
- Fluent request builder API
- Response analysis with status byte logic
- Full compatibility with existing task system

## Components

### HTTPClient ([client.go](client.go))
Wraps Go's `net/http.Client` with middleware support:
- Implements `mock.HTTPClient` interface
- TLS verification disabled by default (configurable)
- Connection pooling (100 max idle, 10 per host)
- Redirect handling (configurable max redirects)

```go
client := http.NewClient(&http.ClientConfig{
    PoolConfig: http.DefaultPoolConfig(),
    Middleware: []http.Middleware{
        http.RetryMiddleware(http.DefaultRetryConfig()),
    },
    MaxRedirects:   10,
    RequestTimeout: 30 * time.Second,
})
```

### Middleware ([middleware.go](middleware.go))

**RetryMiddleware**: Exponential backoff retry logic
- Default: 3 attempts, 100ms initial backoff
- Retries on network errors and configurable status codes
- Respects context cancellation

**RateLimitMiddleware**: Token bucket rate limiting
- Default: 10 requests/second, burst 20
- Smooth rate limiting with refill
- Context-aware blocking

### RequestBuilder ([request.go](request.go))
Fluent API for building HTTP requests:

```go
req, err := http.NewRequest("https://example.com/api").
    POST().
    Header("Authorization", "Bearer token").
    ContentType("application/json").
    BodyString(`{"key":"value"}`).
    Build()
```

Methods:
- `Method(string)`, `GET()`, `POST()`, `HEAD()`
- `Header(key, value)`, `Headers(map)`
- `UserAgent(ua)`, `ContentType(ct)`
- `Body([]byte)`, `BodyString(string)`
- `Context(ctx)`, `Depth(int)`
- `Clone()`, `WithPath(path)`, `AppendPath(segment)`
- `WithQueryParam(key, value)`

### ResponseAnalyzer ([analyzer.go](analyzer.go))
Analyzes HTTP responses and determines status bytes:

```go
analyzer := http.NewResponseAnalyzer()
status, err := analyzer.Analyze(response)

if analyzer.IsValidResource(status) {
    // Found valid resource
}
```

Status bytes (matches Burp Suite):
- `0`: Unknown/NotFound (404)
- `1`: Found (200-399)
- `2`: Error (500+)
- `3`: Unauthorized (401, 403)
- `4`: Streaming (chunked transfer)

### Response Utilities ([response.go](response.go))
Helper functions for response processing:
- `ParseContentType()`: Extracts media type, charset, classification
- `IsSuccessStatus()`, `IsRedirectStatus()`, etc.
- `ExtractMetadata()`: Comprehensive response metadata

### Connection Pool ([pool.go](pool.go))
Configures `http.Transport` with:
- MaxIdleConns: 100
- MaxIdleConnsPerHost: 10
- TLS InsecureSkipVerify: true (for testing arbitrary targets)
- Keep-alive, idle timeout, dial timeout configuration

### Error Types ([errors.go](errors.go))
Specialized error types:
- `RequestError`: HTTP request failures with retry attempt tracking
- `RateLimitError`: Rate limit violations
- `IsRetryable(err)`: Determines if error should trigger retry

## Usage with Discovery Engine

The HTTP client integrates seamlessly with the existing task system:

```go
import (
    infrahttp "github.com/burp/god/internal/infrastructure/http"
    "github.com/burp/god/internal/domain/discovery"
)

// Create HTTP client
client := infrahttp.NewClient(&infrahttp.ClientConfig{
    PoolConfig: infrahttp.DefaultPoolConfig(),
    Middleware: []infrahttp.Middleware{
        infrahttp.RetryMiddleware(&infrahttp.RetryConfig{
            MaxAttempts:          3,
            InitialBackoff:       100 * time.Millisecond,
            RetryableStatusCodes: []int{429, 503},
        }),
        infrahttp.RateLimitMiddleware(&infrahttp.RateLimitConfig{
            RequestsPerSecond: 10,
            BurstSize:         20,
        }),
    },
    RequestTimeout: 30 * time.Second,
})

// Create response analyzer
analyzer := infrahttp.NewResponseAnalyzer()

// Create task with real HTTP client
task := discovery.NewWordlistTask(&discovery.WordlistTaskConfig{
    TaskType:   discovery.ShortFilesNoExt,
    Provider:   payloadProvider,
    BaseURL:    []byte("https://example.com/"),
    Depth:      0,
})
```

## Configuration

### TLS Verification
By default, TLS verification is **disabled** to allow testing arbitrary targets (common for security tools). To enable:

```go
poolConfig := http.DefaultPoolConfig()
poolConfig.DisableTLSVerification = false

client := http.NewClient(&http.ClientConfig{
    PoolConfig: poolConfig,
})
```

### Timeouts
Multiple timeout layers:
- Connection dial: 30s (pool config)
- TLS handshake: 10s (pool config)
- Per-request: configurable via `ClientConfig.RequestTimeout`
- Task execution: 30s (worker context)

### Rate Limiting
Token bucket algorithm:
- Fills at `RequestsPerSecond` rate
- Allows bursts up to `BurstSize`
- Blocks when bucket empty (context-aware)

## Testing

Run tests:
```bash
go test ./internal/infrastructure/http/...
```

Coverage:
- Unit tests for all components
- Integration tests with `httptest`
- Middleware behavior validation
- Error handling scenarios

## Week 5 Deliverables

✅ HTTP client with connection pooling
✅ Retry middleware with exponential backoff
✅ Client-level request timeout configuration
✅ Rate limit middleware (token bucket)
✅ Request builder with fluent API
✅ Response analyzer with status byte logic
✅ Full test coverage
✅ Integration with existing task system

## Next Steps (Week 6)

- Fingerprint cache implementation
- Soft 404 detection with 3-baseline sampling
- Status byte 2 (needs fingerprint check) logic
- 38 fingerprint attributes extraction

## References

- Architecture: [docs/architecture/04-http-pipeline.md](../../../docs/architecture/04-http-pipeline.md)
- Burp Source: cq5.java (HTTP executor), er3.java (request generator), gnn.java (response analyzer)
- Go 1.25: native `net/http` with RoundTripper middleware pattern
