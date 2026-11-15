package cli

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// `log <prefix>` resolves an 8+ character UUID prefix like record refs do.
func TestLogUUIDPrefix(t *testing.T) {
	e := newB5Env(t)
	code, _, stderr := e.run(t, nil, "db", "seed", "-j")
	require.Equal(t, 0, code, stderr)

	const seeded = "scan-0001-aaaa-bbbb-cccc-ddddeeee0001"
	code, stdout, stderr := e.run(t, nil, "log", seeded[:14], "-j")
	require.Equal(t, 0, code, stderr)
	doc := oneDoc(t, stdout, stderr)
	require.Equal(t, seeded, doc["uuid"])

	// Every seeded scan starts "scan-000", so that prefix is ambiguous.
	code, stdout, stderr = e.run(t, nil, "log", "scan-000", "-j")
	require.NotEqual(t, 0, code)
	require.Contains(t, stdout, "ambiguous_id", stderr)
}
