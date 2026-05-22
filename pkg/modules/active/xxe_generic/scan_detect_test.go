package xxe_generic

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

const seedXML = `<?xml version="1.0" encoding="UTF-8"?><order><item>1</item></order>`

// TestScanPerRequest_DetectsXXE drives the real scan method against an endpoint
// whose XML parser resolves external entities. When the injected payload
// references file:///etc/passwd, the server (simulating a vulnerable parser)
// returns the file contents, so the module observes the "root:" marker that was
// absent from the original response — confirming in-band XXE.
func TestScanPerRequest_DetectsXXE(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		if strings.Contains(string(body), "etc/passwd") {
			// Vulnerable parser expands the entity into the response.
			_, _ = w.Write([]byte("<result>root:x:0:0:root:/root:/bin/bash\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin</result>"))
			return
		}
		_, _ = w.Write([]byte("<result>ok</result>"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.RequestMethod(t, "POST", srv.URL+"/api/orders", seedXML)

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected an XXE finding when /etc/passwd is reflected")
	assert.Contains(t, res[0].ExtractedResults, "root:")
}

// TestScanPerRequest_NoFalsePositive ensures a hardened parser that never
// resolves external entities (returns a fixed benign body) yields no finding.
func TestScanPerRequest_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<result>order accepted</result>"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.RequestMethod(t, "POST", srv.URL+"/api/orders", seedXML)

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a parser that ignores external entities must not yield an XXE finding")
}

// TestCanProcess gates on XML-ish requests: XML content types, XML Accept
// headers, or XML-looking bodies are processable; plain JSON is not.
func TestCanProcess(t *testing.T) {
	t.Parallel()
	m := New()

	xmlReq := modtest.RequestMethod(t, "POST", "http://example.com/api", seedXML)
	assert.True(t, m.CanProcess(xmlReq), "an XML body should be processable")

	jsonReq := modtest.RequestMethod(t, "POST", "http://example.com/api", `{"id":1}`)
	assert.False(t, m.CanProcess(jsonReq), "a plain JSON body should not be processable")
}
