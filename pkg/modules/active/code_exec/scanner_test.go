package code_exec

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// TestGetPayloadsForExtension checks payload selection: generic Unix and Windows
// payloads are always present, and language-specific payloads are added only
// when the path extension maps to a known language.
func TestGetPayloadsForExtension(t *testing.T) {
	contains := func(set []string, want string) bool {
		for _, s := range set {
			if s == want {
				return true
			}
		}
		return false
	}

	genericCount := len(genericUnixPayloads) + len(windowsPayloads)

	t.Run("no extension yields only generic payloads", func(t *testing.T) {
		raw := []byte("GET /search?cmd=1 HTTP/1.1\r\nHost: example.com\r\n\r\n")
		got := getPayloadsForExtension(raw)
		assert.Subset(t, got, genericUnixPayloads, "generic Unix payloads must always be present")
		assert.Subset(t, got, windowsPayloads, "Windows payloads must always be present")
		// Len equality (not just Subset) guards against spurious extra payloads leaking in.
		assert.Len(t, got, genericCount, "no language payloads expected without a matching extension")
	})

	t.Run("asp/aspx map to \"any\" which has no language payloads", func(t *testing.T) {
		// extensionMap[".asp"/".aspx"] == "any", but langPayloads has no "any"
		// key, so the lookup misses and only generic payloads apply.
		for _, path := range []string{"/page.asp", "/page.aspx"} {
			raw := []byte("GET " + path + "?cmd=1 HTTP/1.1\r\nHost: example.com\r\n\r\n")
			got := getPayloadsForExtension(raw)
			assert.Len(t, got, genericCount, "%s maps to \"any\" (no langPayloads entry)", path)
		}
	})

	t.Run("php extension adds php payloads", func(t *testing.T) {
		raw := []byte("GET /shell.php?cmd=1 HTTP/1.1\r\nHost: example.com\r\n\r\n")
		got := getPayloadsForExtension(raw)
		for _, p := range langPayloads["php"] {
			assert.True(t, contains(got, p), "expected php payload %q for a .php path", p)
		}
	})

	t.Run("python extension adds python payloads", func(t *testing.T) {
		raw := []byte("GET /app.py?cmd=1 HTTP/1.1\r\nHost: example.com\r\n\r\n")
		got := getPayloadsForExtension(raw)
		for _, p := range langPayloads["python"] {
			assert.True(t, contains(got, p), "expected python payload %q for a .py path", p)
		}
	})

	t.Run("unknown extension yields only generic payloads", func(t *testing.T) {
		raw := []byte("GET /file.unknownext?cmd=1 HTTP/1.1\r\nHost: example.com\r\n\r\n")
		got := getPayloadsForExtension(raw)
		assert.Len(t, got, len(genericUnixPayloads)+len(windowsPayloads))
	})
}

// TestScanPerRequest_NoFalsePositiveFastServer guards the time-based detector's
// negative path: a server that always responds immediately must never be
// flagged, since no probe crosses the delay threshold. (The positive,
// time-delayed path is covered by the e2e/xbow-cmdi suite, which can afford the
// multi-probe 10s sleeps that would make a unit test slow and flaky.)
func TestScanPerRequest_NoFalsePositiveFastServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok") // instant response
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/run?cmd=ls")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a consistently fast server must not yield a command-injection finding")
}
