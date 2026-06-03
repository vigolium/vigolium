package cors_misconfiguration

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

func TestNew(t *testing.T) {
	m := New()
	assert.Equal(t, "cors-misconfiguration", m.ID())
	assert.Equal(t, "CORS Misconfiguration", m.Name())
	assert.Equal(t, severity.Low, m.Severity())
	assert.Equal(t, severity.Firm, m.Confidence())
	assert.Equal(t, modkit.ScanScopeHost, m.ScanScopes())
}

func TestCanProcess(t *testing.T) {
	m := New()

	t.Run("nil context", func(t *testing.T) {
		assert.False(t, m.CanProcess(nil))
	})

	t.Run("no request", func(t *testing.T) {
		ctx := httpmsg.NewHttpRequestResponse(nil, nil)
		assert.False(t, m.CanProcess(ctx))
	})

	t.Run("request without response", func(t *testing.T) {
		raw := "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
		ctx, err := httpmsg.ParseRawRequest(raw)
		require.NoError(t, err)
		assert.False(t, m.CanProcess(ctx))
	})

	t.Run("request with response", func(t *testing.T) {
		raw := "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
		ctx, err := httpmsg.ParseRawRequest(raw)
		require.NoError(t, err)

		resp := httpmsg.NewHttpResponse([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
		ctxWithResp := httpmsg.NewHttpRequestResponse(ctx.Request(), resp)
		assert.True(t, m.CanProcess(ctxWithResp))
	})
}

func TestProbeChecks(t *testing.T) {
	t.Run("reflected origin", func(t *testing.T) {
		p := probes[0]
		assert.Equal(t, "Reflected Origin", p.name)
		assert.Equal(t, severity.Low, p.sev)

		// Positive: ACAO matches evil origin
		assert.True(t, p.check("https://evil.example.com", ""))
		assert.True(t, p.check("https://evil.example.com", "true"))

		// Negative: ACAO doesn't match
		assert.False(t, p.check("https://example.com", ""))
		assert.False(t, p.check("*", ""))
		assert.False(t, p.check("", ""))
	})

	t.Run("null origin", func(t *testing.T) {
		p := probes[1]
		assert.Equal(t, "Null Origin", p.name)
		assert.Equal(t, severity.Low, p.sev)

		// Positive: ACAO is null
		assert.True(t, p.check("null", ""))
		assert.True(t, p.check("null", "true"))

		// Negative: ACAO is not null
		assert.False(t, p.check("*", ""))
		assert.False(t, p.check("", ""))
		assert.False(t, p.check("https://example.com", ""))
	})

	t.Run("wildcard with credentials", func(t *testing.T) {
		p := probes[2]
		assert.Equal(t, "Wildcard with Credentials", p.name)
		assert.Equal(t, severity.Low, p.sev)

		// Positive: ACAO is * and ACAC is true
		assert.True(t, p.check("*", "true"))
		assert.True(t, p.check("*", "True")) // case-insensitive

		// Negative: missing one condition
		assert.False(t, p.check("*", ""))
		assert.False(t, p.check("*", "false"))
		assert.False(t, p.check("https://example.com", "true"))
		assert.False(t, p.check("", "true"))
	})

	t.Run("subdomain bypass check function", func(t *testing.T) {
		p := probes[3]
		assert.Equal(t, "Subdomain Bypass", p.name)
		assert.Equal(t, severity.Low, p.sev)

		// The check function just verifies ACAO is non-empty
		// (actual origin matching is done by the caller in runProbe)
		assert.True(t, p.check("https://evil.example.com", ""))
		assert.False(t, p.check("", ""))
	})

	t.Run("subdomain bypass origin function", func(t *testing.T) {
		p := probes[3]
		require.NotNil(t, p.originFunc)

		assert.Equal(t, "https://evil.example.com", p.originFunc("example.com"))
		assert.Equal(t, "https://evil.target.io", p.originFunc("target.io"))
	})
}

func TestProbeCount(t *testing.T) {
	assert.Len(t, probes, 8, "expected exactly 8 CORS probes")
}

func TestProbeOrigins(t *testing.T) {
	// Reflected Origin
	assert.Equal(t, "https://evil.example.com", probes[0].origin)
	assert.Nil(t, probes[0].originFunc)

	// Null Origin
	assert.Equal(t, "null", probes[1].origin)
	assert.Nil(t, probes[1].originFunc)

	// Wildcard with Credentials
	assert.Equal(t, "https://example.com", probes[2].origin)
	assert.Nil(t, probes[2].originFunc)

	// Subdomain Bypass
	assert.Equal(t, "", probes[3].origin)
	assert.NotNil(t, probes[3].originFunc)
}
