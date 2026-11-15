package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"

	fileutil "github.com/projectdiscovery/utils/file"
	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/agent"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/terminal"
	"go.uber.org/zap"
)

// readStdinIfPiped reads stdin when something is actually piped into it, for
// the commands that fall back to stdin only when no other input was given
// (autopilot, replay, swarm, fuzz).
//
// fileutil.HasStdin is the one "is stdin piped" test. It is true for any stdin
// that is not a terminal, including a pipe a parent process opened and never
// writes to, so the read is implicit: it gets the short first-byte window
// (implicitStdinWait) and nothing within it, or an empty pipe, is reported as
// not piped — ("", false, nil). A producer that starts and then fails (a stall
// past --input-read-timeout, input over the size limit, a read error) is an
// error. That used to be swallowed into "no target", which pointed the caller
// at the wrong problem.
func readStdinIfPiped() (data string, ok bool, err error) {
	if !fileutil.HasStdin() {
		return "", false, nil
	}
	raw, err := readImplicitStdin()
	if err != nil {
		if errors.Is(err, clicommon.ErrStdinNoData) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("failed to read stdin: %w", err)
	}
	if len(raw) == 0 {
		return "", false, nil
	}
	return strings.TrimRight(string(raw), "\n\r"), true, nil
}

// resolveInstruction returns the instruction text from either --instruction or --instruction-file.
// If both are provided, --instruction-file takes precedence.
func resolveInstruction(instruction, instructionFile string) (string, error) {
	if instructionFile != "" {
		data, err := os.ReadFile(instructionFile)
		if err != nil {
			return "", fmt.Errorf("failed to read instruction file %q: %w", instructionFile, err)
		}
		return strings.TrimRight(string(data), "\n\r"), nil
	}
	return instruction, nil
}

// resolvePlanFile reads a --plan-file and splits it into a free-text
// instruction and zero or more raw HTTP request blocks (seed inputs).
//
// --plan-file is the single-file front end for "prose guidance + raw
// request(s)". It owns both the instruction and the seed input, so combining
// it with --input (which would supply the seed) is rejected up front to avoid
// ambiguity over which value wins; combining it with a prompt (--prompt /
// positional) is rejected earlier in resolveRawPrompt. Returns an error if the
// file is missing/unreadable or yields neither an instruction nor a request.
func resolvePlanFile(path, input string) (planInstruction string, requests []string, err error) {
	if input != "" {
		return "", nil, usageErrorf("--plan-file cannot be combined with --input")
	}
	data, rerr := os.ReadFile(path)
	if rerr != nil {
		return "", nil, fmt.Errorf("failed to read plan file %q: %w", path, rerr)
	}
	pi, reqs := agent.ParsePlanFile(string(data))
	if strings.TrimSpace(pi) == "" && len(reqs) == 0 {
		return "", nil, fmt.Errorf("plan file %q has no instruction or HTTP request", path)
	}
	return pi, reqs, nil
}

// appendExtraRequests folds additional plan-file request blocks into the
// instruction as labelled context. Used by single-seed callers (autopilot):
// the first request is the live seed, the rest steer the operator agent.
func appendExtraRequests(instruction string, extras []string) string {
	if len(extras) == 0 {
		return instruction
	}
	var b strings.Builder
	if strings.TrimSpace(instruction) != "" {
		b.WriteString(instruction)
		b.WriteString("\n\n")
	}
	b.WriteString("Additional related requests to consider (same scope; vary/compare against the primary seed request):\n")
	for i, r := range extras {
		fmt.Fprintf(&b, "\n--- additional request %d ---\n%s\n", i+1, strings.TrimSpace(r))
	}
	return strings.TrimRight(b.String(), "\n")
}

// resolveSystemPrompt returns the system-prompt text from either --system-prompt
// or --system-prompt-file. --system-prompt-file takes precedence when both are
// provided. The returned string fully replaces the built-in autopilot system
// prompt at the call site — there is no append mode.
func resolveSystemPrompt(prompt, promptFile string) (string, error) {
	if promptFile != "" {
		data, err := os.ReadFile(promptFile)
		if err != nil {
			return "", fmt.Errorf("failed to read system-prompt file %q: %w", promptFile, err)
		}
		return strings.TrimRight(string(data), "\n\r"), nil
	}
	return prompt, nil
}

// resolveTargetFromInput normalizes a raw input string (curl, raw HTTP, Burp XML, URL)
// and extracts the target URL. Used by autopilot and pipeline commands to derive --target
// from --input or piped stdin.
func resolveTargetFromInput(ctx context.Context, input string, repo *database.Repository) (string, error) {
	targetURL, err := agent.TargetURLFromInput(ctx, input, "", repo)
	if err != nil {
		return "", fmt.Errorf("failed to extract target URL from input: %w", err)
	}
	return targetURL, nil
}

// ResolvedInput holds the result of resolving raw input and target from CLI flags/stdin.
type ResolvedInput struct {
	Target    string // resolved target URL
	InputData string // raw input data (may be empty)
}

// resolveInputAndTarget resolves the --input and --target flags, reading from stdin if needed,
// and deriving the target URL from the input when --target is not provided.
// The repo is required for record-UUID inputs (looked up from the database);
// other input shapes (URL, curl, raw HTTP, Burp XML, base64) work with a nil repo.
// This is the shared implementation used by autopilot, pipeline, and swarm commands.
func resolveInputAndTarget(target, input string, repo *database.Repository) (*ResolvedInput, error) {
	inputData := input
	if inputData == "-" {
		data, err := readStdin()
		if err != nil {
			return nil, fmt.Errorf("failed to read from stdin: %w", err)
		}
		inputData = string(data)
	} else if inputData == "" && target == "" {
		data, ok, err := readStdinIfPiped()
		if err != nil {
			return nil, err
		}
		if ok {
			inputData = data
		}
	}

	// Derive target from input when --target is not provided
	resolvedTarget := target
	if resolvedTarget == "" && inputData != "" {
		ctx := context.Background()
		targetURL, err := resolveTargetFromInput(ctx, inputData, repo)
		if err != nil {
			return nil, fmt.Errorf("could not derive target from input: %w\nUse --target to specify explicitly", err)
		}
		resolvedTarget = targetURL
	}

	return &ResolvedInput{
		Target:    resolvedTarget,
		InputData: inputData,
	}, nil
}

// promptDryRunView is the --dry-run document for a natural-language prompt.
type promptDryRunView struct {
	Raw         string            `json:"raw"`
	ModelParsed bool              `json:"model_parsed"`
	Apps        []agent.AppIntent `json:"apps"`
	Note        string            `json:"note"`
}

// printPromptDryRun previews a natural-language agent prompt without the
// model: a prompt that is already a URL resolves offline; anything else is
// reported unparsed, since parsing it is a provider call.
func printPromptDryRun(cmd *cobra.Command, prompt string) error {
	view := promptDryRunView{Raw: strings.TrimSpace(prompt), Apps: []agent.AppIntent{}}
	if intent := agent.StructuredIntent(prompt); intent != nil {
		view.Apps = intent.Apps
		view.Note = "dry run: the prompt is a structured input and resolved without the model; nothing was sent"
	} else {
		view.Note = "dry run: a natural-language prompt is parsed by the model at run time, which --dry-run does not call; pass -t/--source to preview the rendered prompts"
	}
	if globalJSON {
		return emitObject(cmd, ".", view)
	}
	for _, app := range view.Apps {
		fmt.Printf("target: %s\n", firstNonEmptyString(app.Target, app.SourcePath))
	}
	fmt.Fprintf(os.Stderr, "%s %s\n", terminal.InfoSymbol(), view.Note)
	return nil
}

// loadCLISettings loads settings, falling back to defaults on error so the
// CLI can keep working with reasonable behavior even if the YAML is unreadable.
// The fallback is announced rather than logged — see settingsOrDefaults.
func loadCLISettings() *config.Settings {
	return settingsOrDefaults()
}

// parsePromptIntent is the shared scaffold for both runAutopilotFromPrompt and
// runSwarmFromPrompt. It opens the DB, creates an engine, parses the natural
// language prompt, and resolves targets. The caller is responsible for closing
// the returned engine.
func parsePromptIntent(settings *config.Settings, prompt string) (*agent.ScanIntent, *agent.Engine, *database.Repository, error) {
	var repo *database.Repository
	db, dbErr := getDB()
	if dbErr == nil {
		ctx := context.Background()
		if schemaErr := db.CreateSchema(ctx); schemaErr != nil {
			zap.L().Warn("Failed to create schema", zap.Error(schemaErr))
		}
		repo = database.NewRepository(db)
	}

	engine := agent.NewEngine(settings, repo)

	fmt.Fprintf(os.Stderr, "%s Parsing natural language prompt...\n", terminal.InfoSymbol())

	sessionsDir := settings.Agent.EffectiveSessionsDir()
	intent, err := agent.ParseAndResolveIntent(context.Background(), engine, prompt,
		agent.WithSessionsDir(sessionsDir))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to parse scan prompt: %w", err)
	}

	return intent, engine, repo, nil
}

// parsePromptFirstApp runs the LLM intent parser on prompt purely to recover its
// first AppIntent — used by autopilot/swarm on the explicit-flag path to pull
// auth/browser signals out of a prompt that is otherwise forwarded verbatim.
// Unlike parsePromptIntent it uses ParseScanIntent (no target resolution) and
// the already-open repo.
//
// The intent parser is instructed to return {"apps":[]} when it finds no target
// or source in the text, so a credential-only prompt (e.g. "log in as
// admin/admin123, focus on /admin") on an explicit -t/--source run would yield
// nothing and the credentials would be silently dropped. targetHint/sourceHint
// (the already-resolved explicit-flag target/source) are woven in as an anchor
// so the parser still emits an app carrying the extracted auth/browser signals;
// only those signals are consumed by the caller — the target/source stay owned
// by the explicit flags. Returns ok=false for an empty prompt, a parse error
// (logged under label), or when no apps were extracted.
func parsePromptFirstApp(settings *config.Settings, repo *database.Repository, prompt, label, targetHint, sourceHint string) (agent.AppIntent, bool) {
	if strings.TrimSpace(prompt) == "" {
		return agent.AppIntent{}, false
	}
	engine := agent.NewEngine(settings, repo)
	intent, err := agent.ParseScanIntent(context.Background(), engine, anchorIntentPrompt(prompt, targetHint, sourceHint),
		agent.WithSessionsDir(settings.Agent.EffectiveSessionsDir()))
	if err != nil || intent == nil || len(intent.Apps) == 0 {
		if err != nil {
			zap.L().Debug(label+": prompt auth extraction failed", zap.Error(err))
		}
		return agent.AppIntent{}, false
	}
	return intent.Apps[0], true
}

// anchorIntentPrompt prefixes prompt with the resolved target/source so the
// intent parser has a target to anchor on and does not bail with {"apps":[]}
// for a credential-only prompt. The "Scan target:"/"Source path:" labels keep
// the combined text from tripping ParseScanIntent's structured-input fast path
// (DetectInputType only matches a bare URL/curl/HTTP/base64 prefix).
func anchorIntentPrompt(prompt, targetHint, sourceHint string) string {
	var b strings.Builder
	if t := strings.TrimSpace(targetHint); t != "" {
		b.WriteString("Scan target: ")
		b.WriteString(t)
		b.WriteByte('\n')
	}
	if s := strings.TrimSpace(sourceHint); s != "" {
		b.WriteString("Source path: ")
		b.WriteString(s)
		b.WriteByte('\n')
	}
	b.WriteString(prompt)
	return b.String()
}

// guardOrRefuseFromPrompt loads settings and runs the prompt-safety classifier
// (unless disabled). On refusal it prints the verdict + bypass tip and returns
// a wrapped agent.ErrPromptRefused. On allow (or skip) it returns the loaded
// settings so the caller doesn't have to load them again.
func guardOrRefuseFromPrompt(ctx context.Context, prompt string, disabled bool) (*config.Settings, error) {
	settings := loadCLISettings()
	if disabled {
		fmt.Fprintf(os.Stderr, "%s Guardrail disabled (--disable-guardrail)\n", terminal.WarningSymbol())
		return settings, nil
	}
	fmt.Fprintf(os.Stderr, "%s Checking prompt with safety guardrail...\n", terminal.InfoSymbol())
	fmt.Fprintf(os.Stderr, "%s Tip: pass %s to skip this check — recommended for trusted pentest prompts and local/quantized models that false-positive.\n",
		terminal.InfoSymbol(), terminal.Cyan("--disable-guardrail"))
	verdict := agent.ClassifyPromptSafety(ctx, settings, prompt)
	if verdict.Allowed {
		return settings, nil
	}
	fmt.Fprintf(os.Stderr, "\n%s Prompt refused by guardrail: %s\n",
		terminal.ErrorSymbol(), verdict.Reason)
	if len(verdict.Categories) > 0 {
		fmt.Fprintf(os.Stderr, "%s Categories: %s\n",
			terminal.InfoSymbol(), strings.Join(verdict.Categories, ", "))
	}
	fmt.Fprintf(os.Stderr, "%s Bypass with --disable-guardrail if this is a false positive.\n",
		terminal.InfoSymbol())
	return settings, agent.RefusalError(verdict)
}

// runMultiAppFanOut runs a function for each app in the intent, in parallel,
// and collects errors. This is the shared fan-out logic for both autopilot and swarm.
func runMultiAppFanOut(ctx context.Context, intent *agent.ScanIntent, runFn func(ctx context.Context, idx int, app agent.AppIntent) error) error {
	type appResult struct {
		index int
		err   error
	}

	results := make(chan appResult, len(intent.Apps))
	var wg sync.WaitGroup

	for i, app := range intent.Apps {
		wg.Add(1)
		go func(idx int, app agent.AppIntent) {
			defer wg.Done()
			results <- appResult{index: idx, err: runFn(ctx, idx, app)}
		}(i, app)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	var errs []string
	for r := range results {
		if r.err != nil {
			errs = recordAppError(errs, intent.Apps[r.index], r.err)
		}
	}
	return summarizeMultiAppResults(errs, len(intent.Apps))
}

// runMultiAppSequential runs runFn for each app in the intent one at a time,
// aggregating errors the same way runMultiAppFanOut does. Unlike the parallel
// fan-out, this never runs two apps concurrently — callers that override shared
// package-level flags per app (autopilot) require serialization to avoid a race
// that would cross-contaminate targets/sources. Stops launching new apps once
// the context is cancelled/timed out.
func runMultiAppSequential(ctx context.Context, intent *agent.ScanIntent, runFn func(ctx context.Context, idx int, app agent.AppIntent) error) error {
	var errs []string
	for i, app := range intent.Apps {
		if err := ctx.Err(); err != nil {
			errs = append(errs, fmt.Sprintf("[app %d] skipped: %v", i+1, err))
			continue
		}
		if err := runFn(ctx, i, app); err != nil {
			errs = recordAppError(errs, app, err)
		}
	}
	return summarizeMultiAppResults(errs, len(intent.Apps))
}

// appLabel is the operator-facing name for an app in multi-app output —
// its source path if any, else its target URL.
func appLabel(app agent.AppIntent) string {
	if app.SourcePath != "" {
		return app.SourcePath
	}
	return app.Target
}

// recordAppError prints a per-app failure line and appends a labeled entry to
// errs, returning the extended slice. Shared by the parallel and sequential
// multi-app schedulers.
func recordAppError(errs []string, app agent.AppIntent, err error) []string {
	label := appLabel(app)
	fmt.Fprintf(os.Stderr, "%s App %q failed: %v\n", terminal.ErrorSymbol(), label, err)
	return append(errs, fmt.Sprintf("[%s] %v", label, err))
}

// summarizeMultiAppResults renders the final multi-app outcome: an aggregate
// error when any app failed, otherwise an "all complete" line and nil.
func summarizeMultiAppResults(errs []string, total int) error {
	if len(errs) > 0 {
		return fmt.Errorf("%d/%d apps failed:\n  %s", len(errs), total, strings.Join(errs, "\n  "))
	}
	fmt.Fprintf(os.Stderr, "\n%s All %d runs complete\n", terminal.SuccessSymbol(), total)
	return nil
}

// mergeIntentInstruction merges the base instruction with the app-specific
// instruction extracted by the natural-language intent parser.
func mergeIntentInstruction(base string, app agent.AppIntent) string {
	instruction := base
	if app.Instruction != "" {
		if instruction != "" {
			instruction += "\n\n"
		}
		instruction += app.Instruction
	}
	return instruction
}

// prependVerbatimPrompt puts the verbatim natural-language prompt in front of
// the resolved instruction. The verbatim prompt comes first because it carries
// the user's primary intent (and any exploitation hints they wrote); the
// resolved instruction (--plan-file / intent-parsed) layers on top of that.
func prependVerbatimPrompt(instruction, verbatim string) string {
	if verbatim == "" {
		return instruction
	}
	if instruction == "" {
		return verbatim
	}
	return verbatim + "\n\n" + instruction
}

// resolveRawPrompt returns the single free-text task-guidance string shared by
// `agent autopilot` and `agent swarm`. The guidance can come from the positional
// [prompt] argument, the --prompt flag, or the --prompt-file flag (three
// spellings of the same input — --prompt-file just reads the file for you so a
// long/complex prompt needn't be shell-escaped); supplying more than one is an
// error. It rejects combining a prompt with --plan-file, which owns the
// instruction channel. Returns the trimmed prompt ("" when none). The caller
// decides — from its own hasExplicitFlags — whether the prompt drives the run
// through the natural-language intent parser or is preserved verbatim as
// instruction context (a non-empty planFile always implies explicit flags, so
// the guard fires only in the explicit-flags branch).
//
// --prompt-file is deliberately the SAME channel as --prompt, not a --plan-file
// alias: its contents flow through the intent parser + credential extraction, so
// role-tagged accounts in the file are stood up as primary/compare sessions.
// --plan-file skips that extraction (it owns a different, seed-request channel).
func resolveRawPrompt(args []string, promptFlag, promptFile, planFile string) (string, error) {
	prompt := strings.TrimSpace(promptFlag)
	if len(args) > 0 {
		if pos := strings.TrimSpace(args[0]); pos != "" {
			if prompt != "" {
				return "", usageErrorf("pass the task guidance once: use the positional [prompt] or --prompt, not both")
			}
			prompt = pos
		}
	}
	if pf := strings.TrimSpace(promptFile); pf != "" {
		if prompt != "" {
			return "", usageErrorf("pass the task guidance once: use --prompt-file or the positional [prompt]/--prompt, not both")
		}
		data, rerr := os.ReadFile(config.ExpandPath(pf))
		if rerr != nil {
			//vigolium:not-usage file read failure
			return "", fmt.Errorf("--prompt-file %q: %w", pf, rerr)
		}
		prompt = strings.TrimSpace(string(data))
		if prompt == "" {
			//vigolium:not-usage decided from file contents, after I/O
			return "", fmt.Errorf("--prompt-file %q is empty", pf)
		}
	}
	if prompt != "" && planFile != "" {
		return "", usageErrorf("--plan-file cannot be combined with a prompt (--prompt / --prompt-file / positional): the plan file owns the instruction channel; fold the guidance into the plan file instead")
	}
	return prompt, nil
}
