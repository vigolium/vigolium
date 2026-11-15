package cli

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFindingLoadReadsVigoliumDialects(t *testing.T) {
	envelopes := strings.Join([]string{
		`{"type":"http_record","data":{"uuid":"r1"}}`,
		`{"type":"finding","data":{"id":7,"module_id":"xss","module_name":"XSS","severity":"High","url":"https://a.example/x","project_uuid":"other"}}`,
	}, "\n")
	fs, format, err := detectAndParse(envelopes, "", "proj")
	require.NoError(t, err)
	require.Equal(t, "export-jsonl", format)
	require.Len(t, fs, 1)
	require.Zero(t, fs[0].ID, "the source row id must not be reused")
	require.Equal(t, "proj", fs[0].ProjectUUID)
	require.NoError(t, normalizeLoadedFindings(fs))
	require.Equal(t, "high", fs[0].Severity)
	require.Equal(t, "a.example", fs[0].Hostname)

	doc := `{"ok":true,"command":"finding","items":[{"id":3,"module_id":"sqli","module_name":"SQLi","severity":"critical","url":"https://b.example/q","hostname":"b.example","matched_at":["https://b.example/q?id=1"]}]}`
	fs, format, err = detectAndParse(doc, "", "proj")
	require.NoError(t, err)
	require.Equal(t, "finding-json", format)
	require.Equal(t, []string{"https://b.example/q?id=1"}, fs[0].MatchedAt)
}

// An array of agent findings that differ only by URL is that many findings,
// and each keeps its location.
func TestFindingLoadAgentFindingsKeepLocation(t *testing.T) {
	var items []string
	for _, h := range []string{"a", "b", "c", "d", "e"} {
		items = append(items, `{"title":"Open redirect","severity":"medium","url":"https://`+h+`.example/r"}`)
	}
	fs, _, err := detectAndParse("["+strings.Join(items, ",")+"]", "", "proj")
	require.NoError(t, err)
	require.Len(t, fs, 5)
	hashes := map[string]bool{}
	for _, f := range fs {
		require.NotEmpty(t, f.URL)
		require.NotEmpty(t, f.Hostname)
		require.NotEmpty(t, f.MatchedAt)
		hashes[f.FindingHash] = true
	}
	require.Len(t, hashes, 5, "five URLs must hash to five findings")
}

func TestFindingLoadRejectsUnknownSeverity(t *testing.T) {
	fs, _, err := detectAndParse(`{"title":"x","severity":"bogus-sev"}`, "", "proj")
	require.NoError(t, err)
	require.ErrorContains(t, normalizeLoadedFindings(fs), "bogus-sev")
}
