package firebase_auth_misconfig

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// NEEDS-PHASE-3: positive detection probes the real Google Identity Toolkit API
// (identitytoolkit.googleapis.com) using an apiKey extracted from the seed
// response. The module builds raw absolute-URL requests against that fixed
// external host with no service/host override, so anonymous-signup, email
// enumeration, and provider-discovery checks cannot be driven against an
// in-process httptest server; they require a live (or DNS-mocked) Identity
// Toolkit endpoint.

// TestNew_Metadata verifies module construction and identity.
func TestNew_Metadata(t *testing.T) {
	t.Parallel()
	m := New()
	require.NotNil(t, m)
	assert.Equal(t, ModuleID, m.ID())
	assert.NotEmpty(t, m.Name())
	assert.NotEmpty(t, m.ModuleTags)
}

// TestCanProcess covers the response-required guard.
func TestCanProcess(t *testing.T) {
	t.Parallel()
	m := New()
	assert.False(t, m.CanProcess(nil))

	rr := modtest.Request(t, "http://example.com/")
	assert.False(t, m.CanProcess(rr), "no response attached should be rejected")

	withResp := modtest.Response(rr, "text/html", "<html></html>")
	assert.True(t, m.CanProcess(withResp))
}

// TestScanPerRequest_NoAPIKey ensures a body without a Firebase apiKey
// short-circuits with no finding and no outbound probe.
func TestScanPerRequest_NoAPIKey(t *testing.T) {
	t.Parallel()
	client := modtest.Requester(t)
	rr := modtest.Response(
		modtest.Request(t, "http://example.com/"),
		"text/html",
		"<html><body>no firebase api key here</body></html>",
	)

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "no apiKey in body must yield no finding")
}

// TestAPIKeyRegex confirms apiKey extraction from a Firebase config blob.
func TestAPIKeyRegex(t *testing.T) {
	t.Parallel()
	// apiKeyRe requires exactly "AIza" followed by 35 [a-zA-Z0-9_-] chars.
	key := "AIza" + "01234567890123456789012345678901234"
	m := apiKeyRe.FindStringSubmatch(`"apiKey":"` + key + `"`)
	require.Len(t, m, 2)
	assert.Equal(t, key, m[1])

	assert.Nil(t, apiKeyRe.FindStringSubmatch(`"apiKey":"short"`))
}
