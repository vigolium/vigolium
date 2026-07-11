package firebase_rtdb_exposure

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// NEEDS-PHASE-3: positive detection probes real <name>.firebaseio.com hosts
// derived from the seed response body. The module builds raw absolute-URL
// requests against firebaseio.com with no service/host override, so it cannot
// be redirected to an in-process httptest server. Confirming a world-readable
// RTDB requires a live (or mocked-at-DNS-layer) firebaseio.com endpoint.

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

// TestScanPerRequest_NoRTDBURL ensures a response body with no firebaseio.com
// URLs short-circuits with no finding and no outbound probe.
func TestScanPerRequest_NoRTDBURL(t *testing.T) {
	t.Parallel()
	client := modtest.Requester(t)
	rr := modtest.Response(
		modtest.Request(t, "http://example.com/"),
		"text/html",
		"<html><body>nothing firebase here</body></html>",
	)

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "no RTDB URL in body must yield no finding")
}

// TestRTDBURLRegex confirms the database-name extraction regex.
func TestRTDBURLRegex(t *testing.T) {
	t.Parallel()
	m := rtdbURLRe.FindStringSubmatch("see https://my-app-123.firebaseio.com/x")
	require.Len(t, m, 2)
	assert.Equal(t, "my-app-123", m[1])

	assert.Nil(t, rtdbURLRe.FindStringSubmatch("https://example.com/no-match"))
}

// TestSecretPatterns confirms the embedded-secret matchers fire on known shapes.
func TestSecretPatterns(t *testing.T) {
	t.Parallel()
	samples := map[string]string{
		"Private Key": "-----BEGIN PRIVATE KEY-----",
		"Slack Token": "xoxb-1234-" + "abcd",
	}
	// Drive from the known samples (not the pattern list) so a renamed or removed
	// pattern fails the test instead of silently asserting nothing.
	for name, want := range samples {
		var found bool
		for _, sp := range secretPatterns {
			if sp.name == name {
				found = true
				assert.Truef(t, sp.pattern.MatchString(want), "pattern %s should match its sample", name)
				break
			}
		}
		assert.Truef(t, found, "no secret pattern named %q (renamed or removed?)", name)
	}
	for _, pattern := range secretPatterns {
		assert.NotEqual(t, "Google API Key", pattern.name, "Firebase/Google client API keys are publishable identifiers, not private secrets")
	}
}

func TestAssessRTDBDataSeparatesShallowKeysFromSensitiveValues(t *testing.T) {
	t.Parallel()
	assert.Empty(t, assessRTDBData(`{"users":true,"tokens":true}`), "shallow=true key markers are not sensitive values")

	labels := assessRTDBData(`{"users":{"u1":{"email":"alice@example.test","password":"correct horse battery staple"}}}`)
	assert.Contains(t, labels, "sensitive field: email")
	assert.Contains(t, labels, "sensitive field: password")

	googleKey := "AIza" + "01234567890123456789012345678901234"
	assert.Empty(t, assessRTDBData(`{"apiKey":"`+googleKey+`"}`), "a publishable Google client key alone is not a secret finding")
}

// TestLooksLikeRTDBData covers the strict structural gate that decides whether a
// 200 from a Firebase host is genuine, non-trivial database data.
func TestLooksLikeRTDBData(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		body string
		want bool
	}{
		{"real object tree", `{"users":{"u1":{"name":"a"}}}`, true},
		{"non-empty array", `[{"id":1},{"id":2}]`, true},
		{"empty object", `{}`, false},
		{"empty array", `[]`, false},
		{"null", `null`, false},
		{"blank", `   `, false},
		{"error envelope", `{"error":"Permission denied"}`, false},
		{"html error page with 200", `<!DOCTYPE html><html><body>Not Found</body></html>`, false},
		{"bare scalar string", `"hello"`, false},
		{"bare scalar bool", `true`, false},
		{"bare scalar number", `42`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, looksLikeRTDBData(tc.body))
		})
	}
}
