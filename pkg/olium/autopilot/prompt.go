package autopilot

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/vigolium/vigolium/pkg/agent/prompt"
	"github.com/vigolium/vigolium/public"
	"go.uber.org/zap"
)

// systemPromptFile is the basename for the autopilot persona prompt. The same
// name is used for both the embedded preset and the user override.
const systemPromptFile = "olium-system.md"

// claudeCodeSystemPromptFile is the basename for the claude-code variant of
// the autopilot persona prompt. Used when Provider.Name() == "claude-code"
// because that provider runs Claude Code's CLI as a black-box LLM whose
// native Bash/Read/WebFetch tools execute internally — engine-level tools
// like report_finding / halt_scan never get wired in, so the prompt has to
// describe the inline-block protocol instead.
const claudeCodeSystemPromptFile = "olium-system-claudecode.md"

// embeddedSystemPromptPath is the path inside public.StaticFS where the
// baseline prompt ships.
const embeddedSystemPromptPath = "presets/prompts/autopilot/" + systemPromptFile

// embeddedClaudeCodeSystemPromptPath is the embed path for the claude-code
// variant. Same override directory as the baseline.
const embeddedClaudeCodeSystemPromptPath = "presets/prompts/autopilot/" + claudeCodeSystemPromptFile

// minimalFallbackSystemPrompt is used only if both the embed and the user
// override are missing — a real install will never hit this.
const minimalFallbackSystemPrompt = `You are olium, vigolium's autonomous security-audit agent. Investigate with evidence, report concrete findings via report_finding, and call halt_scan when done.`

// loadSystemPromptBase returns the autopilot persona prompt with a short label
// identifying where it came from. Resolution order:
//  1. ~/.vigolium/prompts/olium-system.md (user override)
//  2. embedded public/presets/prompts/autopilot/olium-system.md
//  3. hardcoded minimal fallback
func loadSystemPromptBase() (string, string) {
	return loadPromptFile(systemPromptFile, embeddedSystemPromptPath, minimalFallbackSystemPrompt)
}

// loadClaudeCodeSystemPromptBase returns the claude-code variant of the
// persona prompt. Same resolution order as the baseline.
func loadClaudeCodeSystemPromptBase() (string, string) {
	return loadPromptFile(claudeCodeSystemPromptFile, embeddedClaudeCodeSystemPromptPath, minimalFallbackSystemPrompt)
}

func loadPromptFile(basename, embedPath, fallback string) (string, string) {
	if home, err := os.UserHomeDir(); err == nil {
		path := filepath.Join(home, ".vigolium", "prompts", basename)
		if data, err := os.ReadFile(path); err == nil {
			zap.L().Debug("loaded olium autopilot system prompt from user file", zap.String("path", path))
			return string(data), path
		}
	}
	if data, err := public.StaticFS.ReadFile(embedPath); err == nil {
		return string(data), "embedded:" + embedPath
	}
	zap.L().Warn("olium autopilot system prompt missing from embed; using fallback", zap.String("basename", basename))
	return fallback, "fallback"
}

// buildSystemPrompt assembles the autopilot agent's persona and
// obligations. Skills XML is appended later by the engine; this
// function only contributes the autopilot-specific baseline.
//
// When the provider is claude-code, the claude-code variant of the
// persona prompt is loaded instead — that prompt describes the inline
// FINDING/HALT block protocol that substitutes for engine-level tools,
// since the claude-code provider runs Claude Code's CLI as a black-box
// LLM whose internal Bash/Read/WebFetch tools never surface as engine
// tool calls.
//
// Browser guidance is loaded from public/presets/prompts/autopilot/
// autopilot-browser-section.md (user override at ~/.vigolium/prompts/)
// via the shared prompt.LoadBrowserPromptSection helper so the SDK and
// in-process agents share the same browser instructions.
func buildSystemPrompt(opts Options) string {
	// Full-replace path: when the caller supplies SystemPrompt, hand it to
	// the engine verbatim. We deliberately skip the embedded persona AND
	// the browser addendum — replace means replace, and stitching either
	// of those on top would silently dilute the caller's prompt.
	if strings.TrimSpace(opts.SystemPrompt) != "" {
		return strings.TrimRight(opts.SystemPrompt, "\n")
	}

	var base string
	if isClaudeCodeProvider(opts.Provider) {
		base, _ = loadClaudeCodeSystemPromptBase()
	} else {
		base, _ = loadSystemPromptBase()
	}
	var b strings.Builder
	b.WriteString(strings.TrimRight(base, "\n"))
	if opts.BrowserAvailable {
		if section := strings.TrimSpace(prompt.LoadBrowserPromptSection()); section != "" {
			b.WriteString("\n\n")
			b.WriteString(section)
		}
	}
	return b.String()
}

// isClaudeCodeProvider reports whether the configured provider is the
// claude-code CLI driver. The check goes through Provider.Name() so we
// don't have to import the provider package here (avoids a cycle: the
// engine already imports autopilot indirectly via skills).
func isClaudeCodeProvider(p interface{ Name() string }) bool {
	return p != nil && p.Name() == "claude-code"
}

// buildInitialPrompt frames the first user turn — what to audit, with
// what context, and a nudge toward a structured approach. Everything
// after this is the model's call.
//
// When opts.InitialPrompt is set, it replaces the auto-generated brief
// entirely; opts.Instruction (if also set) is still appended.
func buildInitialPrompt(opts Options) string {
	if opts.InitialPrompt != "" {
		var b strings.Builder
		b.WriteString(strings.TrimRight(opts.InitialPrompt, "\n"))
		if opts.Instruction != "" {
			b.WriteString("\n\n**Additional instruction:** ")
			b.WriteString(opts.Instruction)
		}
		return b.String()
	}

	var b strings.Builder
	b.WriteString("# Autopilot task\n\n")

	if opts.Target != "" {
		fmt.Fprintf(&b, "**Target:** %s\n", opts.Target)
	}
	if opts.SourcePath != "" {
		fmt.Fprintf(&b, "**Source code:** %s (you have full filesystem read/write access)\n", opts.SourcePath)
	}
	if len(opts.Scope) > 0 {
		fmt.Fprintf(&b, "**Scope:** %s\n", strings.Join(opts.Scope, ", "))
	}
	if opts.Focus != "" {
		fmt.Fprintf(&b, "**Focus:** %s\n", opts.Focus)
	}
	b.WriteString("\n")

	// Mode hint based on available context.
	switch {
	case opts.SourcePath != "" && opts.Target != "":
		b.WriteString("Both source and live target are available — use them together. ")
		b.WriteString("Read the code to find what's risky, then probe the live target to confirm exploitability.\n\n")
	case opts.SourcePath != "":
		b.WriteString("Whitebox audit. Navigate the source tree, find risky code, verify exploitability from the code alone, and report concrete issues with file:line evidence.\n\n")
	default:
		b.WriteString("Blackbox audit. Probe the live target. Confirm issues with specific HTTP request/response evidence.\n\n")
	}

	b.WriteString(`Plan briefly, then execute. Use tools freely — bash, grep, read_file,
web_fetch, etc. Report findings as you confirm them. When you've covered the
scope and have nothing productive left to investigate, call halt_scan with a
short summary reason.

Before your first tool call this turn, write a 1–3 line plan: what you
learned from the prior turn (if any), the hypothesis you're testing now,
and the tool(s) you're about to invoke. Silent tool-only turns are a
bug — always narrate the intent first.`)

	if opts.Instruction != "" {
		b.WriteString("\n\n**Additional instruction:** ")
		b.WriteString(opts.Instruction)
	}

	return b.String()
}
