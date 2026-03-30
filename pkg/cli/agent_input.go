package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/agent"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/terminal"
	"go.uber.org/zap"
)

// stdinIsPiped returns true if stdin is a pipe (not a terminal).
func stdinIsPiped() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) == 0
}

// readStdinIfPiped reads all data from stdin if it's a pipe.
// Returns the data and true if stdin was piped, or empty string and false otherwise.
func readStdinIfPiped() (string, bool) {
	if !stdinIsPiped() {
		return "", false
	}
	data, err := io.ReadAll(os.Stdin)
	if err != nil || len(data) == 0 {
		return "", false
	}
	return strings.TrimRight(string(data), "\n\r"), true
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
// This is the shared implementation used by autopilot, pipeline, and swarm commands.
func resolveInputAndTarget(target, input string) (*ResolvedInput, error) {
	inputData := input
	if inputData == "-" {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return nil, fmt.Errorf("failed to read from stdin: %w", err)
		}
		inputData = string(data)
	} else if inputData == "" && target == "" {
		if data, ok := readStdinIfPiped(); ok {
			inputData = data
		}
	}

	// Derive target from input when --target is not provided
	resolvedTarget := target
	if resolvedTarget == "" && inputData != "" {
		ctx := context.Background()
		targetURL, err := resolveTargetFromInput(ctx, inputData, nil)
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

// printIntentDryRun prints the parsed ScanIntent as JSON and exits.
func printIntentDryRun(intent *agent.ScanIntent) error {
	data, err := json.MarshalIndent(intent, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal intent: %w", err)
	}
	fmt.Println(string(data))
	return nil
}

// valueOrNone returns the value or "(none)" if empty.
func valueOrNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

// parsePromptIntent is the shared scaffold for both runAutopilotFromPrompt and
// runSwarmFromPrompt. It loads settings, opens the DB, creates an engine,
// parses the natural language prompt, and resolves targets.
// The caller is responsible for closing the returned engine.
func parsePromptIntent(prompt string) (*agent.ScanIntent, *agent.Engine, *config.Settings, *database.Repository, error) {
	settings, err := config.LoadSettings(globalConfig)
	if err != nil {
		zap.L().Warn("Failed to load settings, using defaults", zap.Error(err))
		settings = config.DefaultSettings()
	}

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
		engine.Close()
		return nil, nil, nil, nil, fmt.Errorf("failed to parse scan prompt: %w", err)
	}

	return intent, engine, settings, repo, nil
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
			app := intent.Apps[r.index]
			label := app.SourcePath
			if label == "" {
				label = app.Target
			}
			errs = append(errs, fmt.Sprintf("[%s] %v", label, r.err))
			fmt.Fprintf(os.Stderr, "%s App %q failed: %v\n",
				terminal.ErrorSymbol(), label, r.err)
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("%d/%d apps failed:\n  %s", len(errs), len(intent.Apps), strings.Join(errs, "\n  "))
	}

	fmt.Fprintf(os.Stderr, "\n%s All %d runs complete\n",
		terminal.SuccessSymbol(), len(intent.Apps))
	return nil
}

// mergeIntentInstruction merges base instruction with app-specific instruction.
func mergeIntentInstruction(base, instructionFile string, app agent.AppIntent) string {
	instruction, _ := resolveInstruction(base, instructionFile)
	if app.Instruction != "" {
		if instruction != "" {
			instruction += "\n\n"
		}
		instruction += app.Instruction
	}
	return instruction
}
