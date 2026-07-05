package tls_protocol_cipher_audit

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// tlsServer starts an httptest TLS server whose listener is pinned to the given
// TLS config (StartTLS fills in a throwaway certificate). The handler is trivial;
// this module only cares about the handshake.
func tlsServer(t *testing.T, cfg *tls.Config) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.TLS = cfg
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func TestScanPerHost_DetectsDeprecatedProtocols(t *testing.T) {
	t.Parallel()
	// Server accepts only TLS 1.0 and 1.1 — both deprecated.
	srv := tlsServer(t, &tls.Config{MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS11}) //nolint:gosec // test fixture

	rr := modtest.Request(t, srv.URL)
	res, err := New().ScanPerHost(rr, nil, &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, res, 1, "expected a weak-TLS finding")

	tags := res[0].Info.Tags
	assert.Contains(t, tags, "tls10")
	assert.Contains(t, tags, "tls11")
}

func TestScanPerHost_DetectsNoForwardSecrecy(t *testing.T) {
	t.Parallel()
	// Modern protocol floor (TLS 1.2). The server offers a forward-secret ECDHE
	// suite (so the default-client baseline handshake succeeds) AND a static-RSA
	// suite (which the no-PFS probe selects) — the realistic "supports both" case.
	srv := tlsServer(t, &tls.Config{ //nolint:gosec // test fixture
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		},
	})

	rr := modtest.Request(t, srv.URL)
	res, err := New().ScanPerHost(rr, nil, &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, res, 1, "expected a no-forward-secrecy finding")

	tags := res[0].Info.Tags
	assert.Contains(t, tags, "no-pfs")
	assert.NotContains(t, tags, "tls10", "a TLS-1.2-floor server must not be flagged for TLS 1.0")
}

func TestScanPerHost_ModernServerNoFinding(t *testing.T) {
	t.Parallel()
	// TLS 1.2+ floor with forward-secret ECDHE AEAD only → nothing to report.
	srv := tlsServer(t, &tls.Config{ //nolint:gosec // test fixture
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		},
	})

	rr := modtest.Request(t, srv.URL)
	res, err := New().ScanPerHost(rr, nil, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a modern TLS 1.2+ ECDHE-AEAD host must not be flagged")
}

func TestScanPerHost_PlainHTTPSkipped(t *testing.T) {
	t.Parallel()
	// A plain-HTTP service must never trigger a speculative 443 handshake.
	rr := modtest.Request(t, "http://127.0.0.1:1/") // unroutable, plain http
	res, err := New().ScanPerHost(rr, nil, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res)
}
