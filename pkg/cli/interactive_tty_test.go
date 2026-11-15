package cli

import (
	"strings"
	"testing"
)

// Commands that need a terminal refuse a headless run as a usage error that
// names the non-interactive form, instead of the TUI library's raw error;
// an empty --stdin prompt is refused before anything is sent.
func TestInteractiveCommandsWithoutTerminal(t *testing.T) {
	st := seedC6Store(t)
	src := t.TempDir()
	for _, c := range []struct {
		args []string
		hint string
	}{
		{[]string{"olium"}, "-p"},
		{[]string{"agent", "triage"}, "agent triage <finding-id>"},
		{[]string{"audit", "--source", src, "-i", "--driver", "audit"}, "without -i"},
		{[]string{"agent", "query", "--stdin"}, "stdin was empty"},
		{[]string{"olium", "-p", "-"}, "non-empty prompt"},
	} {
		code, out, errOut := st.run(t, c.args...)
		if code != 2 || !strings.Contains(out+errOut, c.hint) {
			t.Errorf("%v: exit %d, want 2 naming %q\n%s\n%s", c.args, code, c.hint, out, errOut)
		}
		if strings.Contains(out+errOut, "/dev/tty") {
			t.Errorf("%v: raw TTY error leaked:\n%s", c.args, out+errOut)
		}
	}
}
