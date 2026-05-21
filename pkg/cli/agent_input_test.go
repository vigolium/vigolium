package cli

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vigolium/vigolium/pkg/agent"
)

// TestPrependVerbatimPrompt covers the contract for the natural-language
// prompt → operator-agent instruction channel. The verbatim prompt must come
// FIRST so the user's exact words (including exploitation hints and
// origin/scope constraints) lead the operator's context; --instruction /
// --instruction-file content from the CLI layers on top of that. The three
// edge cases below are the load-bearing ones: both present, only one side
// present, both empty.
func TestPrependVerbatimPrompt(t *testing.T) {
	t.Run("verbatim first, instruction appended", func(t *testing.T) {
		got := prependVerbatimPrompt("focus on auth", "Find XSS at https://target/x. Popup origin must be target.")
		assert.Equal(t,
			"Find XSS at https://target/x. Popup origin must be target.\n\nfocus on auth",
			got,
			"verbatim prompt must precede --instruction content")
	})

	t.Run("only verbatim", func(t *testing.T) {
		got := prependVerbatimPrompt("", "Find XSS at https://target/x.")
		assert.Equal(t, "Find XSS at https://target/x.", got)
	})

	t.Run("only instruction (no verbatim)", func(t *testing.T) {
		got := prependVerbatimPrompt("focus on auth", "")
		assert.Equal(t, "focus on auth", got,
			"no verbatim prefix means the resolved instruction must pass through unchanged")
	})

	t.Run("both empty", func(t *testing.T) {
		assert.Equal(t, "", prependVerbatimPrompt("", ""))
	})
}

// TestMergeIntentInstruction_AppInstructionAppended documents how the
// multi-app fan-out combines a --instruction with each app's per-app
// instruction. Order: base (--instruction) first, then app.Instruction.
// (The verbatim natural-language prompt is layered on top separately by
// prependVerbatimPrompt at the call site — kept distinct so this helper
// stays simple.)
func TestMergeIntentInstruction_AppInstructionAppended(t *testing.T) {
	got := mergeIntentInstruction("global focus: auth", "", agent.AppIntent{
		Instruction: "this app: look at /v2/billing",
	})
	assert.Equal(t,
		"global focus: auth\n\nthis app: look at /v2/billing",
		got)
}
