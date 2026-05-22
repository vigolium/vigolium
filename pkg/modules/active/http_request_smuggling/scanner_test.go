package http_request_smuggling

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

func TestNew(t *testing.T) {
	m := New()
	assert.Equal(t, ModuleID, m.ID())
	assert.Equal(t, ModuleName, m.Name())
	assert.Equal(t, severity.Suspect, m.Severity())
	assert.Equal(t, severity.Tentative, m.Confidence())
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
		ctx, err := httpmsg.ParseRawRequest("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
		require.NoError(t, err)
		assert.False(t, m.CanProcess(ctx), "smuggling needs a baseline response to compare timing against")
	})

	t.Run("request with response", func(t *testing.T) {
		ctx, err := httpmsg.ParseRawRequest("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
		require.NoError(t, err)
		resp := httpmsg.NewHttpResponse([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
		ctxWithResp := httpmsg.NewHttpRequestResponse(ctx.Request(), resp)
		assert.True(t, m.CanProcess(ctxWithResp))
	})
}

// TestProbesWellFormed verifies every desync probe carries the conflicting
// Content-Length / Transfer-Encoding headers that make it a smuggling probe.
// A probe that lost one of these headers (e.g. via a refactor) would silently
// stop testing for desync while still appearing in the probe list.
func TestProbesWellFormed(t *testing.T) {
	assert.NotEmpty(t, probes, "probe table must not be empty")

	names := map[string]struct{}{}
	for i, p := range probes {
		assert.NotEmpty(t, p.name, "probe[%d] must have a name", i)
		assert.NotEmpty(t, p.desc, "probe[%d] (%s) must have a description", i, p.name)
		assert.NotEmpty(t, p.body, "probe[%d] (%s) must have a body", i, p.name)

		_, hasCL := p.headers["Content-Length"]
		_, hasTE := p.headers["Transfer-Encoding"]
		assert.True(t, hasCL, "probe[%d] (%s) must set Content-Length to create a desync", i, p.name)
		assert.True(t, hasTE, "probe[%d] (%s) must set Transfer-Encoding to create a desync", i, p.name)

		if _, dup := names[p.name]; dup {
			t.Errorf("duplicate probe name %q", p.name)
		}
		names[p.name] = struct{}{}
	}
}
