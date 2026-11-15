package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/fuzz"
)

func TestSendOutcomeError(t *testing.T) {
	require.NoError(t, sendOutcomeError("replay", 3, 0))
	require.NoError(t, sendOutcomeError("replay", 0, 0))

	all := sendOutcomeError("replay", 2, 2)
	require.Equal(t, ExitError, classifyExitCode(all))
	require.Equal(t, apicontract.CodeNoTargetsReachable, classifyErrorCode(all, ExitError))

	some := sendOutcomeError("fuzz request", 10, 3)
	require.Equal(t, ExitIncomplete, classifyExitCode(some))
	require.Equal(t, apicontract.CodePartial, classifyErrorCode(some, ExitIncomplete))
}

func TestFuzzBaselineUnreachableCode(t *testing.T) {
	err := fmt.Errorf("fuzz.Run: %w (refused)", fuzz.ErrBaselineUnreachable)
	require.Equal(t, apicontract.CodeNoTargetsReachable, classifyErrorCode(err, classifyExitCode(err)))
}

// ingest names a missing, a directory and an unparseable input instead of
// reporting zero records with exit 0.
func TestIngestRejectsUnusableSources(t *testing.T) {
	st := seedC6Store(t)
	dir := t.TempDir()
	junk := filepath.Join(dir, "junk.json")
	require.NoError(t, os.WriteFile(junk, []byte("garbage{{{"), 0o600))
	for name, tc := range map[string]struct {
		input, format, code string
	}{
		"missing":     {filepath.Join(dir, "nope.txt"), "", "source_missing"},
		"directory":   {dir, "", "source_unreadable"},
		"unparseable": {junk, "openapi", "input_unparsed"},
	} {
		args := []string{"ingest", "-i", tc.input, "-j"}
		if tc.format != "" {
			args = append(args, "-I", tc.format)
		}
		code, out, errOut := st.run(t, args...)
		if code != 1 || !strings.Contains(out, `"code":"`+tc.code+`"`) || !strings.Contains(out, `"ok":false`) {
			t.Errorf("%s: exit %d\n%s\n%s", name, code, out, errOut)
		}
	}
}
