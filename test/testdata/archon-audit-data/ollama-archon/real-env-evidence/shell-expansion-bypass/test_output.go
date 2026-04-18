package agent_test

import (
	"testing"

	"github.com/ollama/ollama/x/agent"
)

func TestShellExpansionBypass(t *testing.T) {
	am := agent.NewApprovalManager()

	// Simulate user approving "cat tools/README.md"
	am.AddToAllowlist("bash", map[string]any{"command": "cat tools/README.md"})

	// Test 1: Command substitution bypass
	cmdSubst := "cat tools/$(echo pwned > /tmp/rce-proof)/a.go"
	if am.IsAllowed("bash", map[string]any{"command": cmdSubst}) {
		t.Logf("VULNERABLE: Command substitution '%s' was auto-approved", cmdSubst)
	} else {
		t.Logf("SAFE: Command substitution '%s' was NOT auto-approved", cmdSubst)
	}

	// Test 2: Backtick substitution
	backtick := "cat tools/`id`/a.go"
	if am.IsAllowed("bash", map[string]any{"command": backtick}) {
		t.Logf("VULNERABLE: Backtick '%s' was auto-approved", backtick)
	} else {
		t.Logf("SAFE: Backtick '%s' was NOT auto-approved", backtick)
	}

	// Test 3: Check IsDenied doesn't catch it
	denied, pattern := agent.IsDenied(cmdSubst)
	t.Logf("IsDenied for command substitution: denied=%v pattern=%q", denied, pattern)

	// Test 4: Brace expansion with /etc/passwd (should be caught by deny)
	braceCmd := "cat tools/{Makefile,../../etc/passwd}"
	denied2, pattern2 := agent.IsDenied(braceCmd)
	t.Logf("IsDenied for brace expansion with /etc/passwd: denied=%v pattern=%q", denied2, pattern2)

	// Test 5: Brace expansion without denied paths
	braceCmd2 := "cat tools/{Makefile,../../tmp/secret.txt}"
	denied3, _ := agent.IsDenied(braceCmd2)
	if !denied3 && am.IsAllowed("bash", map[string]any{"command": braceCmd2}) {
		t.Logf("VULNERABLE: Brace expansion '%s' was auto-approved and not denied", braceCmd2)
	} else {
		t.Logf("Result for brace expansion: denied=%v, allowed=%v", denied3, am.IsAllowed("bash", map[string]any{"command": braceCmd2}))
	}
}
