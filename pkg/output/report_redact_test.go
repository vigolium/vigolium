package output

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// SAFE-12: SARIF (and every report built on buildReportData) carries
// <redacted> instead of credentials by default; NoRedact keeps them.
func TestSARIFRedactsEvidence(t *testing.T) {
	items := []any{findingEnvelope(map[string]any{
		"id": 1, "module_id": "sqli", "module_name": "SQLi", "severity": "high",
		"url":      "https://app.test/x?token=URLSECRET",
		"request":  "GET /x?token=URLSECRET HTTP/1.1\r\nHost: app.test\r\nAuthorization: Bearer AUTHSECRET\r\nX-Op-Header: OPSECRET\r\nCookie: sid=COOKIESECRET\r\n\r\n",
		"response": "HTTP/1.1 200 OK\r\nSet-Cookie: sid=SETSECRET; Path=/\r\n\r\nbody",
	})}
	meta := HTMLReportMeta{RedactHeaders: map[string]struct{}{"x-op-header": {}}}
	raw, err := json.Marshal(buildSARIFLog(items, meta))
	require.NoError(t, err)
	out := string(raw)
	for _, secret := range []string{"URLSECRET", "AUTHSECRET", "OPSECRET", "COOKIESECRET", "SETSECRET"} {
		if strings.Contains(out, secret) {
			t.Errorf("SARIF leaks %s", secret)
		}
	}
	if !strings.Contains(out, "redacted") {
		t.Error("SARIF must carry the redaction placeholder")
	}

	raw, err = json.Marshal(buildSARIFLog(items, HTMLReportMeta{NoRedact: true}))
	require.NoError(t, err)
	if !strings.Contains(string(raw), "AUTHSECRET") {
		t.Error("NoRedact must keep the raw evidence")
	}
}
