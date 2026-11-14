package source

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// WriteCensusHAR writes a HAR with app.test×5 then cdn.other×3 (cdn first in
// file order would change the primary, so app.test leads).
func writeCensusHAR(t *testing.T) string {
	t.Helper()
	var entries []string
	for i := 0; i < 5; i++ {
		entries = append(entries, fmt.Sprintf(`{"request":{"method":"GET","url":"https://app.test/p%d"},"response":{"status":200,"content":{"text":"x"}}}`, i))
	}
	for i := 0; i < 3; i++ {
		entries = append(entries, fmt.Sprintf(`{"request":{"method":"GET","url":"https://cdn.other/s%d.js"},"response":{"status":200,"content":{"text":"x"}}}`, i))
	}
	p := filepath.Join(t.TempDir(), "capture.har")
	require.NoError(t, os.WriteFile(p, []byte(`{"log":{"version":"1.2","entries":[`+strings.Join(entries, ",")+`]}}`), 0o600))
	return p
}

// SAFE-4: the census counts records per host and names the first record's
// host as primary.
func TestHostCensus_HAR(t *testing.T) {
	census, primary, err := HostCensus(writeCensusHAR(t), "har")
	require.NoError(t, err)
	require.Equal(t, "app.test", primary)
	require.Equal(t, map[string]int{"app.test": 5, "cdn.other": 3}, census)
}

// The URL-list default is displaced by content detection, as NewFileSource does.
func TestHostCensus_DetectsFormat(t *testing.T) {
	census, primary, err := HostCensus(writeCensusHAR(t), "urls")
	require.NoError(t, err)
	require.Equal(t, "app.test", primary)
	require.Len(t, census, 2)
}

func TestHostCensus_OpenAPIServers(t *testing.T) {
	spec := `{"openapi":"3.0.0","info":{"title":"t","version":"1"},
"servers":[{"url":"https://api.app.test/v1"},{"url":"https://sandbox.vendor.test"}],
"paths":{"/x":{"get":{"responses":{"200":{"description":"ok"}}}}}}`
	p := filepath.Join(t.TempDir(), "spec.json")
	require.NoError(t, os.WriteFile(p, []byte(spec), 0o600))
	census, primary, err := HostCensus(p, "openapi")
	require.NoError(t, err)
	require.Equal(t, "api.app.test", primary)
	require.Equal(t, map[string]int{"api.app.test": 1, "sandbox.vendor.test": 1}, census)
}
