package cli

import "testing"

// SAFE-5: an unknown --scope-origin is a usage error (exit 2), not a scan in
// an admit-everything mode.
func TestValidateScopeOrigin(t *testing.T) {
	err := validateScopeOrigin("bogus")
	if err == nil {
		t.Fatal("bogus --scope-origin accepted")
	}
	if code := classifyExitCode(err); code != ExitUsageError {
		t.Errorf("exit code = %d, want %d", code, ExitUsageError)
	}
	for _, ok := range []string{"", "all", "relaxed", "balanced", "Strict"} {
		if err := validateScopeOrigin(ok); err != nil {
			t.Errorf("%q rejected: %v", ok, err)
		}
	}
	// The root pre-run applies it to every command that binds the flag.
	saved := globalScopeOrigin
	defer func() { globalScopeOrigin = saved }()
	globalScopeOrigin = "bogus"
	if err := rootCmd.PersistentPreRunE(rootCmd, nil); err == nil || classifyExitCode(err) != ExitUsageError {
		t.Errorf("root pre-run with bogus --scope-origin: err=%v", err)
	}
}
