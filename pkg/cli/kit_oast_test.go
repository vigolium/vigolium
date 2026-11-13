package cli

import "testing"

func TestResolveKitOASTToken(t *testing.T) {
	t.Setenv(kitOASTTokenEnv, "from-env")
	if got := resolveKitOASTToken(""); got != "from-env" {
		t.Errorf("empty flag: got %q, want the env value", got)
	}
	if got := resolveKitOASTToken("from-flag"); got != "from-flag" {
		t.Errorf("explicit flag: got %q, want the flag value", got)
	}
	t.Setenv(kitOASTTokenEnv, "")
	if got := resolveKitOASTToken(""); got != "" {
		t.Errorf("neither set: got %q, want empty", got)
	}
}
