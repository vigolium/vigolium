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

	// Cloudflare stamps Server and Cf-Ray on every response it proxies: on a
	// 403/503 they say the edge is in the path, not that it answered.
	t.Run("presence headers alone on a 403 are not a block", func(t *testing.T) {
		for _, status := range []int{403, 503} {
			rc := createTestResponseChain(status, http.Header{
				"Cf-Ray": []string{"abc123-IAD"},
				"Server": []string{"cloudflare"},
			}, `{"error":"you do not own this order"}`)
			result := detector.Detect(rc)
			rc.Close()
			assert.Nil(t, result, "status %d", status)
		}
	})

	t.Run("detects its block page behind the presence headers", func(t *testing.T) {
		rc := createTestResponseChain(403, http.Header{
			"Cf-Ray": []string{"abc123-IAD"},
			"Server": []string{"cloudflare"},
		}, `<div class="cf-wrapper"><div id="cf-error-details">Sorry, you have been blocked</div></div>`)
		defer rc.Close()
		result := detector.Detect(rc)
		require.NotNil(t, result)
		assert.True(t, result.IsBlocked)
		assert.Equal(t, "cloudflare", result.WAFType)
		assert.Contains(t, result.Indicators, "body: cloudflare block page")
	})

	t.Run("cf-mitigated alone is a block", func(t *testing.T) {
		rc := createTestResponseChain(403, http.Header{"Cf-Mitigated": []string{"challenge"}}, "")
		defer rc.Close()
		result := detector.Detect(rc)
		require.NotNil(t, result)
		assert.Equal(t, "cloudflare", result.WAFType)
	})

	t.Run("presence header on an edge-authored 52x is a block", func(t *testing.T) {
		rc := createTestResponseChain(522, http.Header{"Server": []string{"cloudflare"}}, "")
		defer rc.Close()
		result := detector.Detect(rc)
		require.NotNil(t, result)
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

	t.Run("server header alone on a 403 is not a block", func(t *testing.T) {
		rc := createTestResponseChain(403, http.Header{
			"Server": []string{"AkamaiGHost"},
		}, `{"error":"insufficient_scope"}`)
		defer rc.Close()
		assert.Nil(t, detector.Detect(rc))
	})

	t.Run("detects its access denied page behind the server header", func(t *testing.T) {
		rc := createTestResponseChain(403, http.Header{
			"Server": []string{"AkamaiGHost"},
		}, `<H1>Access Denied</H1>Reference&#32;&#35;18&#46;2f1c1702<P>https&#58;&#47;&#47;errors&#46;edgesuite&#46;net`)
		defer rc.Close()
		result := detector.Detect(rc)
		require.NotNil(t, result)
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

	t.Run("x-akamai-transformed on a 429 is a block", func(t *testing.T) {
		rc := createTestResponseChain(429, http.Header{
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

	t.Run("x-iinfo alone on a 403 is not a block", func(t *testing.T) {
		rc := createTestResponseChain(403, http.Header{
			"X-Iinfo": []string{"10-12345678-12345678 NNNY RT(1234567890123 0) q(0 0 0 0) r(0 0)"},
		}, "")
		defer rc.Close()
		assert.Nil(t, detector.Detect(rc))
	})

	t.Run("detects by incident ID in body", func(t *testing.T) {
		rc := createTestResponseChain(403, make(http.Header), `<html><body>Request unsuccessful. Incapsula incident ID: 123000000012345678-123456789012345678</body></html>`)
		defer rc.Close()
		result := detector.Detect(rc)
		require.NotNil(t, result)
		assert.True(t, result.IsBlocked)
		assert.Equal(t, "imperva", result.WAFType)
	})

	t.Run("detects its resource page behind the x-cdn header", func(t *testing.T) {
		rc := createTestResponseChain(403, http.Header{
			"X-Cdn": []string{"Incapsula CDN"},
		}, `<script src="/_Incapsula_Resource?SWJIYLWA=5074a744"></script>`)
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

func TestDetector_Azure(t *testing.T) {
	detector := NewDetector()

	t.Run("detects application gateway by server header", func(t *testing.T) {
		rc := createTestResponseChain(403, http.Header{
			"Server": []string{"Microsoft-Azure-Application-Gateway/v2"},
		}, "")
		defer rc.Close()
		result := detector.Detect(rc)
		require.NotNil(t, result)
		assert.Equal(t, "azure", result.WAFType)
	})

	t.Run("generic 'The request is blocked' body alone is not azure", func(t *testing.T) {
		// A plain application 403 that happens to say "The request is blocked"
		// must not be misattributed to Azure and trip the discovery circuit
		// breaker. Without a vendor-specific signal it is not a WAF block.
		rc := createTestResponseChain(403, http.Header{
			"Server":       []string{"nginx"},
			"Content-Type": []string{"text/plain"},
		}, "The request is blocked")
		defer rc.Close()
		result := detector.Detect(rc)
		assert.Nil(t, result, "generic phrase alone should not classify as azure")
	})

	t.Run("generic phrase counts once a strong signal corroborates", func(t *testing.T) {
		rc := createTestResponseChain(403, http.Header{
			"X-Azure-Ref": []string{"0abc123"},
		}, "The request is blocked")
		defer rc.Close()
		result := detector.Detect(rc)
		require.NotNil(t, result)
		assert.Equal(t, "azure", result.WAFType)
	})
}

func TestDetector_FortiWeb(t *testing.T) {
	detector := NewDetector()

	t.Run("detects by set-cookie", func(t *testing.T) {
		rc := createTestResponseChain(403, http.Header{
			"Set-Cookie": []string{"other=1", "FORTIWAFSID=0123456789abcdef; path=/"},
		}, "")
		defer rc.Close()
		result := detector.Detect(rc)
		require.NotNil(t, result)
		assert.Equal(t, "fortiweb", result.WAFType)
	})

	t.Run("detects block page body", func(t *testing.T) {
		rc := createTestResponseChain(403, make(http.Header), `<html><title>Web Page Blocked</title><body><img class=".fgd_icon"></body></html>`)
		defer rc.Close()
		result := detector.Detect(rc)
		require.NotNil(t, result)
		assert.Equal(t, "fortiweb", result.WAFType)
	})
}

func TestDetector_Barracuda(t *testing.T) {
	detector := NewDetector()

	t.Run("detects by barracuda cookie not first in set-cookie", func(t *testing.T) {
		rc := createTestResponseChain(403, http.Header{
			"Set-Cookie": []string{"sessionid=abc", "BNI__BARRACUDA_LB_COOKIE=00000; path=/"},
		}, "")
		defer rc.Close()
		result := detector.Detect(rc)
		require.NotNil(t, result)
		assert.Equal(t, "barracuda", result.WAFType)
	})
}

func TestDetector_CitrixNetScaler(t *testing.T) {
	detector := NewDetector()

	t.Run("detects mangled connection header", func(t *testing.T) {
		rc := createTestResponseChain(403, http.Header{
			"Cneonction": []string{"close"},
		}, "")
		defer rc.Close()
		result := detector.Detect(rc)
		require.NotNil(t, result)
		assert.Equal(t, "citrix_netscaler", result.WAFType)
	})

	t.Run("detects ns_af cookie", func(t *testing.T) {
		rc := createTestResponseChain(403, http.Header{
			"Set-Cookie": []string{"ns_af=abc123; path=/"},
		}, "")
		defer rc.Close()
		result := detector.Detect(rc)
		require.NotNil(t, result)
		assert.Equal(t, "citrix_netscaler", result.WAFType)
	})
}

func TestDetector_Wallarm(t *testing.T) {
	detector := NewDetector()

	rc := createTestResponseChain(403, http.Header{
		"Server": []string{"nginx-wallarm"},
	}, "")
	defer rc.Close()
	result := detector.Detect(rc)
	require.NotNil(t, result)
	assert.Equal(t, "wallarm", result.WAFType)
}

func TestDetector_Wordfence(t *testing.T) {
	detector := NewDetector()

	rc := createTestResponseChain(503, make(http.Header),
		`<html><body>Your access to this site has been limited by the site owner. Generated by Wordfence.</body></html>`)
	defer rc.Close()
	result := detector.Detect(rc)
	require.NotNil(t, result)
	assert.Equal(t, "wordfence", result.WAFType)
}

func TestDetector_DataDome(t *testing.T) {
	detector := NewDetector()

	t.Run("detects by x-datadome header", func(t *testing.T) {
		rc := createTestResponseChain(403, http.Header{
			"X-Datadome": []string{"protected"},
		}, "")
		defer rc.Close()
		result := detector.Detect(rc)
		require.NotNil(t, result)
		assert.Equal(t, "datadome", result.WAFType)
	})

	t.Run("detects captcha challenge body", func(t *testing.T) {
		rc := createTestResponseChain(403, http.Header{
			"Set-Cookie": []string{"datadome=abcdef; Path=/; Secure"},
		}, `<html><body><iframe src="https://geo.captcha-delivery.com/captcha/"></iframe></body></html>`)
		defer rc.Close()
		result := detector.Detect(rc)
		require.NotNil(t, result)
		assert.Equal(t, "datadome", result.WAFType)
	})
}

func TestDetector_PerimeterX(t *testing.T) {
	detector := NewDetector()

	t.Run("detects block page body", func(t *testing.T) {
		rc := createTestResponseChain(403, make(http.Header),
			`<html><body>Access to this page has been denied because we believe you are using automation tools to browse the website. <a href="https://www.perimeterx.com/whywasiblocked">details</a></body></html>`)
		defer rc.Close()
		result := detector.Detect(rc)
		require.NotNil(t, result)
		assert.Equal(t, "perimeterx", result.WAFType)
	})

	t.Run("detects _px cookie", func(t *testing.T) {
		rc := createTestResponseChain(403, http.Header{
			"Set-Cookie": []string{"visitor=1", "_pxhd=abc123:def456; Path=/"},
		}, "")
		defer rc.Close()
		result := detector.Detect(rc)
		require.NotNil(t, result)
		assert.Equal(t, "perimeterx", result.WAFType)
	})
}

func TestDetector_Kasada(t *testing.T) {
	detector := NewDetector()

	rc := createTestResponseChain(429, http.Header{
		"X-Kpsdk-Ct": []string{"tokentokentoken"},
	}, "")
	defer rc.Close()
	result := detector.Detect(rc)
	require.NotNil(t, result)
	assert.Equal(t, "kasada", result.WAFType)
}

func TestDetector_QueueIt(t *testing.T) {
	detector := NewDetector()

	rc := createTestResponseChain(503, make(http.Header),
		`<html><body>You are now in line. <script src="https://static.queue-it.net/script.js"></script></body></html>`)
	defer rc.Close()
	result := detector.Detect(rc)
	require.NotNil(t, result)
	assert.Equal(t, "queue_it", result.WAFType)
}

// TestDetector_BotVendorsIgnoreHealthyStatus guards the key false-positive path:
// bot-management cookies (datadome, _px*) ride ordinary 200 responses too, so the
// classifier must not treat a healthy page as a block just because the host is
// behind a bot manager.
func TestDetector_BotVendorsIgnoreHealthyStatus(t *testing.T) {
	detector := NewDetector()

	for _, tc := range []struct {
		name   string
		cookie string
	}{
		{"datadome", "datadome=abc; Path=/"},
		{"perimeterx", "_pxhd=abc:def; Path=/"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rc := createTestResponseChain(200, http.Header{
				"Set-Cookie": []string{tc.cookie},
			}, `<html><body>welcome</body></html>`)
			defer rc.Close()
			assert.Nil(t, detector.Detect(rc), "200 with a %s cookie must not be a block", tc.name)
		})
	}
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

	// Cloudflare is detected before generic when both match.
	rc := createTestResponseChain(403, http.Header{
		"Server": []string{"cloudflare"},
	}, `<html><title>Attention Required! | Cloudflare</title><body>Access Denied</body></html>`) // Matches generic too
	defer rc.Close()

	result := detector.Detect(rc)
	require.NotNil(t, result)
	assert.Equal(t, "cloudflare", result.WAFType, "Cloudflare should be detected before generic")

	// A generic phrase behind Cloudflare's presence header is not Cloudflare's
	// (nor Akamai's, whose "Access Denied" is a weak check): it falls to generic.
	rc2 := createTestResponseChain(403, http.Header{
		"Server": []string{"cloudflare"},
	}, `<html><body>Access Denied</body></html>`)
	defer rc2.Close()
	result = detector.Detect(rc2)
	require.NotNil(t, result)
	assert.Equal(t, "generic", result.WAFType)
}

func TestIsBlockingStatusCode(t *testing.T) {
	blockingCodes := []int{403, 405, 406, 429, 501, 503, 520, 521, 522, 523, 524, 525, 526}
	for _, code := range blockingCodes {
		assert.True(t, IsBlockStatusCode(code), "status %d should be blocking", code)
	}

	nonBlockingCodes := []int{200, 201, 204, 301, 302, 304, 400, 401, 404, 500, 502}
	for _, code := range nonBlockingCodes {
		assert.False(t, IsBlockStatusCode(code), "status %d should not be blocking", code)
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
