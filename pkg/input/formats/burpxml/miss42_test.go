package burpxml

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

func writeXML(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "items.xml")
	require.NoError(t, os.WriteFile(p, []byte(body), 0o600))
	return p
}

// TestParse_AttachesRecordedResponse: the recorded response rides along so an
// imported item costs no re-fetch.
func TestParse_AttachesRecordedResponse(t *testing.T) {
	path := writeXML(t, testXML)
	var got []*httpmsg.HttpRequestResponse
	require.NoError(t, New().Parse(path, func(rr *httpmsg.HttpRequestResponse) bool {
		got = append(got, rr)
		return true
	}))
	require.NotEmpty(t, got)
	resp := got[0].Response()
	require.NotNil(t, resp, "the base64 <response> must be attached")
	assert.Equal(t, 200, resp.StatusCode())
	assert.Contains(t, string(resp.Body()), `{"id":1}`)
}

// TestParse_TruncatedFileErrors: a decode error past the first item must fail
// the import rather than report success with a partial result.
func TestParse_TruncatedFileErrors(t *testing.T) {
	full := testXML
	cut := strings.Index(full, "<item>")
	second := strings.Index(full[cut+1:], "<item>") + cut + 1
	truncated := full[:second+40] // inside the second item
	path := writeXML(t, truncated)
	n := 0
	err := New().Parse(path, func(*httpmsg.HttpRequestResponse) bool {
		n++
		return true
	})
	require.Error(t, err, "a truncated export must not import silently")
	assert.Equal(t, 1, n, "items before the corruption are still delivered")
}
