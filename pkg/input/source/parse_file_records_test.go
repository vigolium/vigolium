package source

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseFileRecords_HAR(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "flows.har")
	har := `{"log":{"version":"1.2","entries":[` +
		`{"request":{"method":"GET","url":"https://acme.test/a"},"response":{"status":200,"content":{"text":"[]"}}},` +
		`{"request":{"method":"POST","url":"https://acme.test/b"},"response":{"status":201,"content":{"text":"ok"}}}` +
		`]}}`
	require.NoError(t, os.WriteFile(p, []byte(har), 0o600))

	recs, err := ParseFileRecords(p, "har", 0)
	require.NoError(t, err)
	require.Len(t, recs, 2)

	// max caps the returned count.
	capped, err := ParseFileRecords(p, "har", 1)
	require.NoError(t, err)
	require.Len(t, capped, 1)
}

func TestParseFileRecords_UnknownFormat(t *testing.T) {
	_, err := ParseFileRecords("/nonexistent", "not-a-format", 0)
	require.Error(t, err)
}
