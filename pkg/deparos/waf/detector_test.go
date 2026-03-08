package waf

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/deparos/responsechain"
)

// createTestResponseChain creates a ResponseChain for testing.
func createTestResponseChain(statusCode int, headers http.Header, body string) *responsechain.ResponseChain {
	resp := &http.Response{
		StatusCode: statusCode,
		Header:     headers,
		Body:       io.NopCloser(strings.NewReader(body)),
	}
	rc := responsechain.NewResponseChain(resp, 0)
	_ = rc.Fill()
	return rc
}

func TestNewDetector(t *testing.T) {
	d := NewDetector()
	require.NotNil(t, d)
	// Verify it's the concrete type with rules
	det, ok := d.(*detector)
	require.True(t, ok, "NewDetector should return *detector")
	assert.NotEmpty(t, det.rules)
}

func TestDetector_NilResponseChain(t *testing.T) {
	detector := NewDetector()
	result := detector.Detect(nil)
	assert.Nil(t, result)
}

func TestDetector_NonBlockingStatusCodes(t *testing.T) {
	detector := NewDetector()

	testCases := []int{200, 201, 204, 301, 302, 304, 400, 401, 404, 500, 502}

	for _, statusCode := range testCases {
		t.Run(http.StatusText(statusCode), func(t *testing.T) {
			rc := createTestResponseChain(statusCode, make(http.Header), "")
			defer rc.Close()
			result := detector.Detect(rc)
			assert.Nil(t, result, "status %d should not be detected as WAF block", statusCode)
		})
	}
}

func TestDetector_Cloudflare(t *testing.T) {
	detector := NewDetector()

	t.Run("detects by cf-ray header", func(t *testing.T) {
		rc := createTestResponseChain(403, http.Header{
			"Cf-Ray": []string{"abc123-IAD"},
			"Server": []string{"cloudflare"},
		}, "")
		defer rc.Close()
		result := detector.Detect(rc)
		require.NotNil(t, result)
		assert.True(t, result.IsBlocked)
		assert.Equal(t, "cloudflare", result.WAFType)
	})

	t.Run("detects by error code in body", func(t *testing.T) {
		rc := createTestResponseChain(403, make(http.Header), `<html><title>Access denied | Cloudflare</title><body>Error code: 1020</body></html>`)
		defer rc.Close()
		result := detector.Detect(rc)
		require.NotNil(t, result)
		assert.True(t, result.IsBlocked)
		assert.Equal(t, "cloudflare", result.WAFType)
	})

	t.Run("detects turnstile captcha", func(t *testing.T) {
		rc := createTestResponseChain(403, http.Header{
			"Server": []string{"cloudflare"},
		}, `<html><title>Just a moment...</title><script src="challenges.cloudflare.com/turnstile"></script></html>`)
		defer rc.Close()
		result := detector.Detect(rc)
		require.NotNil(t, result)
		assert.True(t, result.IsBlocked)
		assert.Equal(t, "cloudflare", result.WAFType)
	})

	t.Run("detects rate limit 429", func(t *testing.T) {
		rc := createTestResponseChain(429, http.Header{
			"Server": []string{"cloudflare"},
			"Cf-Ray": []string{"xyz789-SIN"},
		}, "")
		defer rc.Close()
		result := detector.Detect(rc)
		require.NotNil(t, result)
		assert.True(t, result.IsBlocked)
		assert.Equal(t, "cloudflare", result.WAFType)
	})
}

func TestDetector_Akamai(t *testing.T) {
	detector := NewDetector()

	t.Run("detects by server header", func(t *testing.T) {
		rc := createTestResponseChain(403, http.Header{
			"Server": []string{"AkamaiGHost"},
		}, "")
		defer rc.Close()
		result := detector.Detect(rc)
		require.NotNil(t, result)
		assert.True(t, result.IsBlocked)
		assert.Equal(t, "akamai", result.WAFType)
	})

	t.Run("detects by reference ID in body", func(t *testing.T) {
		rc := createTestResponseChain(403, make(http.Header), `<html><body>Access Denied. Reference #18.abc123def.1234567890.abcdef</body></html>`)
		defer rc.Close()
		result := detector.Detect(rc)
		require.NotNil(t, result)
		assert.True(t, result.IsBlocked)
		assert.Equal(t, "akamai", result.WAFType)
	})

	t.Run("detects by x-akamai-transformed header", func(t *testing.T) {
		rc := createTestResponseChain(403, http.Header{
			"X-Akamai-Transformed": []string{"9 12345 0 pmb=mRUM"},
		}, "")
		defer rc.Close()
		result := detector.Detect(rc)
		require.NotNil(t, result)
		assert.True(t, result.IsBlocked)
		assert.Equal(t, "akamai", result.WAFType)
	})
}

func TestDetector_AWSWAF(t *testing.T) {
	detector := NewDetector()

	t.Run("detects by x-amzn-waf-action header", func(t *testing.T) {
		rc := createTestResponseChain(403, http.Header{
			"X-Amzn-Waf-Action": []string{"block"},
		}, "")
		defer rc.Close()
		result := detector.Detect(rc)
		require.NotNil(t, result)
		assert.True(t, result.IsBlocked)
		assert.Equal(t, "aws_waf", result.WAFType)
	})

	t.Run("detects by body content", func(t *testing.T) {
		rc := createTestResponseChain(403, make(http.Header), `<html><body>Request blocked by AWS WAF</body></html>`)
		defer rc.Close()
		result := detector.Detect(rc)
		require.NotNil(t, result)
		assert.True(t, result.IsBlocked)
		assert.Equal(t, "aws_waf", result.WAFType)
	})

	t.Run("detects captcha page", func(t *testing.T) {
		rc := createTestResponseChain(405, http.Header{
			"X-Amz-Cf-Id": []string{"abc123"},
		}, `<html><script src="captcha.awswaf.com/challenge.js"></script><script>window.gokuProps = {}</script></html>`)
		defer rc.Close()
		result := detector.Detect(rc)
		require.NotNil(t, result)
		assert.True(t, result.IsBlocked)
		assert.Equal(t, "aws_waf", result.WAFType)
	})
}

func TestDetector_F5BigIP(t *testing.T) {
	detector := NewDetector()

	t.Run("detects by server header", func(t *testing.T) {
		rc := createTestResponseChain(403, http.Header{
			"Server": []string{"BIG-IP"},
		}, "")
		defer rc.Close()
		result := detector.Detect(rc)
		require.NotNil(t, result)
		assert.True(t, result.IsBlocked)
		assert.Equal(t, "f5_bigip", result.WAFType)
	})

	t.Run("detects by support ID in body", func(t *testing.T) {
		rc := createTestResponseChain(403, make(http.Header), `<html><body>The requested URL was rejected. Your support ID is: 12345678901234567890</body></html>`)
		defer rc.Close()
		result := detector.Detect(rc)
		require.NotNil(t, result)
		assert.True(t, result.IsBlocked)
		assert.Equal(t, "f5_bigip", result.WAFType)
	})
}

func TestDetector_Imperva(t *testing.T) {
	detector := NewDetector()

	t.Run("detects by x-iinfo header", func(t *testing.T) {
		rc := createTestResponseChain(403, http.Header{
			"X-Iinfo": []string{"10-12345678-12345678 NNNY RT(1234567890123 0) q(0 0 0 0) r(0 0)"},
		}, "")
		defer rc.Close()
		result := detector.Detect(rc)
		require.NotNil(t, result)
		assert.True(t, result.IsBlocked)
		assert.Equal(t, "imperva", result.WAFType)
	})

	t.Run("detects by incident ID in body", func(t *testing.T) {
		rc := createTestResponseChain(403, make(http.Header), `<html><body>Request unsuccessful. Incapsula incident ID: 123000000012345678-123456789012345678</body></html>`)
		defer rc.Close()
		result := detector.Detect(rc)
		require.NotNil(t, result)
		assert.True(t, result.IsBlocked)
		assert.Equal(t, "imperva", result.WAFType)
	})

	t.Run("detects by x-cdn header", func(t *testing.T) {
		rc := createTestResponseChain(403, http.Header{
			"X-Cdn": []string{"Incapsula CDN"},
		}, "")
		defer rc.Close()
		result := detector.Detect(rc)
		require.NotNil(t, result)
		assert.True(t, result.IsBlocked)
		assert.Equal(t, "imperva", result.WAFType)
	})
}

func TestDetector_Sucuri(t *testing.T) {
	detector := NewDetector()

	t.Run("detects by server header", func(t *testing.T) {
		rc := createTestResponseChain(403, http.Header{
			"Server": []string{"Sucuri/Cloudproxy"},
		}, "")
		defer rc.Close()
		result := detector.Detect(rc)
		require.NotNil(t, result)
		assert.True(t, result.IsBlocked)
		assert.Equal(t, "sucuri", result.WAFType)
	})

	t.Run("detects by body content", func(t *testing.T) {
		rc := createTestResponseChain(403, make(http.Header), `<html><title>Sucuri Website Firewall</title><body>Sucuri WebSite Firewall - Your request was blocked</body></html>`)
		defer rc.Close()
		result := detector.Detect(rc)
		require.NotNil(t, result)
		assert.True(t, result.IsBlocked)
		assert.Equal(t, "sucuri", result.WAFType)
	})
}

func TestDetector_ModSecurity(t *testing.T) {
	detector := NewDetector()

	t.Run("detects by body content", func(t *testing.T) {
		rc := createTestResponseChain(403, make(http.Header), `<html><body>This error was generated by Mod_Security.</body></html>`)
		defer rc.Close()
		result := detector.Detect(rc)
		require.NotNil(t, result)
		assert.True(t, result.IsBlocked)
		assert.Equal(t, "modsecurity", result.WAFType)
	})

	t.Run("detects NAXSI", func(t *testing.T) {
		rc := createTestResponseChain(403, make(http.Header), `<html><body>Blocked by NAXSI</body></html>`)
		defer rc.Close()
		result := detector.Detect(rc)
		require.NotNil(t, result)
		assert.True(t, result.IsBlocked)
		assert.Equal(t, "modsecurity", result.WAFType)
	})
}

func TestDetector_Generic(t *testing.T) {
	detector := NewDetector()

	t.Run("detects generic access denied", func(t *testing.T) {
		rc := createTestResponseChain(403, make(http.Header), `<html><body>Access Denied</body></html>`)
		defer rc.Close()
		result := detector.Detect(rc)
		require.NotNil(t, result)
		assert.True(t, result.IsBlocked)
		// Could be detected by multiple rules, just check it's blocked
	})

	t.Run("detects rate limit message", func(t *testing.T) {
		rc := createTestResponseChain(429, make(http.Header), `<html><body>Rate limit exceeded. Too many requests.</body></html>`)
		defer rc.Close()
		result := detector.Detect(rc)
		require.NotNil(t, result)
		assert.True(t, result.IsBlocked)
	})
}

func TestDetector_Indicators(t *testing.T) {
	detector := NewDetector()

	rc := createTestResponseChain(403, http.Header{
		"Server": []string{"cloudflare"},
		"Cf-Ray": []string{"abc123-IAD"},
	}, `<html><title>Attention Required! | Cloudflare</title></html>`)
	defer rc.Close()

	result := detector.Detect(rc)
	require.NotNil(t, result)
	assert.True(t, result.IsBlocked)
	assert.NotEmpty(t, result.Indicators)
}

func TestDetector_PriorityOrder(t *testing.T) {
	detector := NewDetector()

	// Test that Cloudflare is detected before generic when both match
	rc := createTestResponseChain(403, http.Header{
		"Server": []string{"cloudflare"},
	}, `<html><body>Access Denied</body></html>`) // Matches generic too
	defer rc.Close()

	result := detector.Detect(rc)
	require.NotNil(t, result)
	assert.Equal(t, "cloudflare", result.WAFType, "Cloudflare should be detected before generic")
}

func TestIsBlockingStatusCode(t *testing.T) {
	blockingCodes := []int{403, 405, 406, 429, 501, 503, 520, 521, 522, 523, 524, 525, 526}
	for _, code := range blockingCodes {
		assert.True(t, isBlockingStatusCode(code), "status %d should be blocking", code)
	}

	nonBlockingCodes := []int{200, 201, 204, 301, 302, 304, 400, 401, 404, 500, 502}
	for _, code := range nonBlockingCodes {
		assert.False(t, isBlockingStatusCode(code), "status %d should not be blocking", code)
	}
}

func BenchmarkDetector_NoMatch(b *testing.B) {
	detector := NewDetector()
	rc := createTestResponseChain(200, make(http.Header), "")
	defer rc.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		detector.Detect(rc)
	}
}

func BenchmarkDetector_CloudflareMatch(b *testing.B) {
	detector := NewDetector()
	rc := createTestResponseChain(403, http.Header{
		"Server": []string{"cloudflare"},
		"Cf-Ray": []string{"abc123-IAD"},
	}, `<html><title>Access denied | Cloudflare</title></html>`)
	defer rc.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		detector.Detect(rc)
	}
}

func BenchmarkDetector_GenericMatch(b *testing.B) {
	detector := NewDetector()
	rc := createTestResponseChain(403, make(http.Header), `<html><body>Access Denied</body></html>`)
	defer rc.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		detector.Detect(rc)
	}
}
