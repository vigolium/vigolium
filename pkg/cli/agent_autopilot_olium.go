package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"io"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/agent"
	"github.com/vigolium/vigolium/pkg/agent/agenttypes"
	"github.com/vigolium/vigolium/pkg/audit/claudecost"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/notify/webhook"
	"github.com/vigolium/vigolium/pkg/olium"
	"github.com/vigolium/vigolium/pkg/olium/autopilot"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"go.uber.org/zap"
)

// runAutopilotOlium is the in-process autopilot path that replaces the
// legacy external-CLI-subprocess dispatch. Invoked from runAgentAutopilot
// when --agent is unset or explicitly "olium".
//
// Responsibilities:
//   - Set up ctx + timeout + signal handling (mirrors the legacy path)
//   - Create a session dir under agent.sessions_dir
//   - Persist a parent AgenticScan row (so `vigolium agent sessions` lists it)
//   - Resolve a olium Provider from defaults (or flags, as they're added)
//   - Drive autopilot.Run, which owns the engine and AI loop
//   - Update the parent row on completion/failure
//   - Print a short summary for the operator
func runAutopilotOlium(parentCtx context.Context, settings *config.Settings, repo *database.Repository, instruction string) error {
	if parentCtx == nil {
		parentCtx = context.Background()
	}
	// Browser is always available for autopilot — force it on regardless of the
	// config default so the operator always gets the browser tool and
	// browser-assisted auth can run. This is the single chokepoint for both the
	// direct and multi-app paths (there is no --browser flag).
	enabledBrowser := true
	settings.Agent.Browser.Enable = &enabledBrowser

	// --dry-run renders the prompts and stops: no session dir, no run row, no
	// pre-scan, no knowledge-base distillation, no provider. Every one of those
	// either sends traffic, calls the model, or records a run that never ran.
	if autopilotDryRun {
		return printAutopilotDryRun(nil, settings, instruction)
	}

	// Ctx + timeout + signal handling — descend from the caller's context so an
	// outer cancellation/timeout (e.g. the multi-app scheduler) actually stops
	// this run, then layer our own timeout + signal handling on top.
	ctx, cancel := context.WithCancel(parentCtx)
	defer cancel()
	if autopilotMaxDuration > 0 {
		ctx, cancel = context.WithTimeout(ctx, autopilotMaxDuration)
		defer cancel()
	}
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		zap.L().Info("Signal received, shutting down olium autopilot")
		cancel()
	}()

	sessionsDir := settings.Agent.EffectiveSessionsDir()
	agenticScanUUID := pinnedOrNewUUID(globalScanUUID)
	var sessionDir string
	var sdErr error
	if autopilotSessionDir != "" {
		// --session-dir: pin the debug-artifact directory explicitly. EnsureSessionDir
		// builds the subdir tree under baseDir/name; the run UUID stays a real UUID
		// (see parentAgenticScanUUID below), so a non-UUID dir name is fine here.
		sessionDir, sdErr = agent.EnsureSessionDir(filepath.Dir(autopilotSessionDir), filepath.Base(autopilotSessionDir))
	} else {
		sessionDir, sdErr = agent.EnsureSessionDir(sessionsDir, agenticScanUUID)
	}
	if sdErr != nil {
		zap.L().Warn("Failed to create session dir", zap.Error(sdErr))
	}
	// The run document lists a session dir that could not be created in
	// errors[] (the run continues without its artifacts).
	outcome := &agentRunOutcome{
		Command:         "agent autopilot",
		Mode:            "autopilot",
		AgenticScanUUID: agenticScanUUID,
		SessionDir:      sessionDir,
		Repo:            repo,
		Budget: agentRunBudget{
			MaxCommands:   autopilotMaxCommands,
			TokenBudget:   autopilotTokenBudget,
			MaxCostUSD:    autopilotMaxCostUSD,
			MaxDurationMS: autopilotMaxDuration.Milliseconds(),
		},
		AuditHarness: &agentAuditHarness{Mode: firstNonEmptyString(autopilotAudit, "off"), Piolium: autopilotPiolium},
	}
	if sdErr != nil {
		outcome.addError(fmt.Errorf("create session dir: %w", sdErr))
	}
	if sessionDir != "" {
		if pidErr := agent.WriteRunPID(sessionDir); pidErr != nil {
			zap.L().Warn("Failed to write PID file", zap.Error(pidErr))
		}
		defer agent.RemoveRunPID(sessionDir)
		// Seed the session dir with on-disk SKILL.md files so the agent can
		// discover them via filesystem tools.
		agent.CopySkillsToSessionDir(sessionDir)
	}

	projectUUID, _ := resolveProjectUUID()
	outcome.ProjectUUID = projectUUID
	if err := prepareAutopilotAuthFiles(ctx, settings, repo, projectUUID, autopilotTarget, autopilotAuthFiles, !autopilotDryRun); err != nil {
		return err
	}

	// Resolve olium provider. CLI --provider overrides agent.olium.provider in
	// the config file; if both are empty, olium auto-detects one.
	oliumCfg := settings.Agent.Olium
	systemPrompt, sysErr := resolveSystemPrompt(autopilotSystemPrompt, autopilotSystemPromptFile)
	if sysErr != nil {
		return sysErr
	}
	effectiveSystemPrompt := firstNonEmptyString(systemPrompt, oliumCfg.SystemPrompt)
	effectiveExtraBody, err := oliumCfg.CustomProvider.EffectiveExtraBody()
	if err != nil {
		return fmt.Errorf("olium custom_provider: %w", err)
	}
	prov, providerName, model, err := olium.ResolveProvider(olium.Options{
		Provider:            firstNonEmptyString(autopilotOliumProvider, oliumCfg.Provider),
		OAuthCredPath:       firstNonEmptyString(autopilotOliumOAuthCred, oliumCfg.OAuthCredPath),
		OAuthToken:          firstNonEmptyString(autopilotOliumOAuthToken, oliumCfg.OAuthToken),
		LLMAPIKey:           firstNonEmptyString(autopilotOliumLLMAPIKey, oliumCfg.LLMAPIKey),
		GoogleCloudProject:  oliumCfg.GoogleCloudProject,
		GoogleCloudLocation: oliumCfg.GoogleCloudLocation,
		Model:               firstNonEmptyString(autopilotOliumModel, oliumCfg.Model),
		SystemPrompt:        effectiveSystemPrompt,
		CustomBaseURL:       oliumCfg.CustomProvider.BaseURL,
		CustomModelID:       oliumCfg.CustomProvider.ModelID,
		CustomAPIKey:        firstNonEmptyString(autopilotOliumLLMAPIKey, oliumCfg.CustomProvider.APIKey, oliumCfg.LLMAPIKey),
		CustomExtraHeaders:  oliumCfg.CustomProvider.ExtraHeadersMap(),
		CustomExtraBody:     effectiveExtraBody,
	})
	if err != nil {
		return agent.NewProviderMissingError(fmt.Errorf("autopilot: resolve provider: %w", err))
	}
	outcome.Provider, outcome.Model = providerName, model
	// Gate provider calls through the shared semaphore so concurrent
	// autopilot sessions don't bypass the cap that swarm/source-analysis
	// already respect. Slot is per-Stream, not per-run.
	prov = agent.WrapProviderWithSemaphore(&oliumCfg, prov)

	// Parent AgenticScan row — matches the session dir's UUID so
	// `vigolium agent sessions` links resolve directly to disk.
	startedAt := time.Now()
	var parentAgenticScanUUID string
	if sessionDir != "" {
		// The real run UUID (not the dir basename) so DB linkage holds even when
		// --session-dir points artifacts at a custom directory.
		parentAgenticScanUUID = agenticScanUUID
	}
	outcome.StartedAt = startedAt
	outcome.AgenticScanUUID = parentAgenticScanUUID
	startAgenticScanRow(ctx, repo, &database.AgenticScan{
		UUID:        parentAgenticScanUUID,
		ProjectUUID: projectUUID,
		ScanUUID:    globalScanUUID,
		Mode:        "autopilot",
		AgentName:   "olium",
		Protocol:    "olium-engine",
		Model:       model,
		TargetURL:   autopilotTarget,
		SourcePath:  autopilotSource,
		SessionDir:  sessionDir,
		StartedAt:   startedAt,
	})
	var stopCancelWatch func()
	ctx, stopCancelWatch = watchAgentCancel(ctx, repo, sessionDir, parentAgenticScanUUID)
	defer stopCancelWatch()

	// Tee streamed text into {sessionDir}/runtime.log so `vigolium log <uuid>`
	// can replay the run later, regardless of whether the operator is watching.
	// agentStreamSink() routes the live stream to stderr under --json so stdout
	// is reserved for the final JSON summary.
	streamWriter := agentStreamSink()
	if tee, closer := teeToRuntimeLog(streamWriter, sessionDir); closer != nil {
		streamWriter = tee
		defer func() { _ = closer.Close() }()
	}

	printAutopilotBanner(autopilotBannerInputs{
		Provider:        providerName,
		Model:           model,
		ProjectUUID:     projectUUID,
		Target:          autopilotTarget,
		SourcePath:      autopilotSource,
		Intensity:       autopilotIntensity,
		MaxCommands:     autopilotMaxCommands,
		MaxDuration:     autopilotMaxDuration,
		AuditDriverMode: autopilotAudit,
		PioliumMode:     autopilotPiolium,
		BrowserEnabled:  settings.Agent.Browser.IsEnabled(),
		NoPrescan:       autopilotNoPrescan,
		SessionDir:      sessionDir,
		AgenticScanUUID: parentAgenticScanUUID,
	})

	// Prior context: front-load a bounded summary of the traffic + findings
	// already in the project DB (Burp imports, prior scans/findings) so the
	// operator mines them instead of re-deriving from scratch. Built here — before
	// this run's pre-scan — so it reflects genuinely prior data, and layered onto
	// both the source (pipeline) and target (pre-scan) paths below.
	if brief, nRec, nFind := buildPriorContextBrief(ctx, repo, projectUUID, autopilotPriorContext); brief != "" {
		fmt.Fprintf(os.Stderr, "%s Prior context: front-loaded %d record(s) · %d finding(s) from the project DB (--prior-context %s)\n",
			terminal.InfoSymbol(), nRec, nFind, autopilotPriorContext)
		if strings.TrimSpace(instruction) != "" {
			instruction = instruction + "\n\n" + brief
		} else {
			instruction = brief
		}
	}

	// Knowledge base: fold operator-supplied reference docs (auth model, login
	// flows, roles, business logic) into the operator's brief. Read-on-demand
	// like --source — only a compact LLM-distilled summary + a document index
	// are inlined here; the full docs stay on disk for the agent to read_file /
	// grep, so a large docs tree never floods the context window. Layered onto
	// `instruction` before the audit-cfg branch so it reaches BOTH the pipeline
	// (whitebox/audit) and direct (blackbox/pre-scan) paths. Failure is
	// non-fatal — the run continues without the brief.
	if kb := strings.TrimSpace(autopilotKnowledgeBase); kb != "" {
		// Traffic half: HTTP-traffic exports in the KB (HAR, Burp, curl, OpenAPI,
		// Postman, URL lists, raw HTTP) are parsed into real http_records and
		// ingested like a Burp import (source=knowledge-base), with a bounded
		// endpoint sample folded into the brief. Gated on a DB repo (records need
		// somewhere to land) and suppressed by --knowledge-base-no-traffic, which
		// then keeps those files in the prose corpus instead.
		routeTraffic := !autopilotKnowledgeBaseNoTraffic && repo != nil
		var kbSections []string
		if routeTraffic {
			if trafficSection, _ := ingestKnowledgeBaseTraffic(ctx, repo, projectUUID, kb, os.Stderr); trafficSection != "" {
				kbSections = append(kbSections, trafficSection)
			}
		}
		// Prose half: distill/index the reference docs. Traffic files are excluded
		// from this corpus when routeTraffic is on (they went to the DB above).
		section, kbErr := buildKnowledgeBaseSection(ctx, prov, model, kb, autopilotKnowledgeBaseRaw, sessionDir, os.Stderr, routeTraffic)
		if kbErr != nil {
			fmt.Fprintf(os.Stderr, "%s Knowledge base: %v — continuing without it\n", terminal.WarningSymbol(), kbErr)
		} else if section != "" {
			kbSections = append(kbSections, section)
		}
		if combined := strings.Join(kbSections, "\n\n"); combined != "" {
			if strings.TrimSpace(instruction) != "" {
				instruction = instruction + "\n\n" + combined
			} else {
				instruction = combined
			}
		}
	}

	// Audit (audit or piolium) runs automatically when --source is set
	// unless --audit=off (and --piolium empty/off).
	if auditCfg, harness := resolveAutopilotAuditCfg(settings); auditCfg != nil {
		outcome.AuditHarness.Harness = harness.Name
		outcome.AuditHarness.AgentCLI = auditHarnessAgentCLI(harness)
		return runAutopilotOliumPipeline(ctx, settings, repo, instruction, auditCfg, harness,
			outcome, streamWriter)
	}

	// Preflight the provider before the pre-scan spends minutes of native
	// scanning on a run whose first model call would fail. (The pipeline path
	// above runs its own, degrading to a blackbox scan on failure.)
	if !autopilotPreflight.skip && !autopilotDryRun {
		if perr := agent.NewEngine(settings, repo).Preflight(ctx); perr != nil {
			end := database.AgenticRunEnd{Err: perr}
			dbStatus, _ := agentRunStatus(end)
			finishAgenticScanRow(repo, parentAgenticScanUUID, startedAt, agenticScanRowFinish{Status: dbStatus, ErrorMessage: perr.Error()})
			return perr
		}
	}

	// Target-only path: run a native pre-scan (discovery + dynamic-assessment
	// + spider) so the operator agent starts with real http_records and
	// findings rather than a cold blackbox. Suppressed via --no-prescan, when
	// the target is empty (source-only run, which auditCfg above already
	// caught), or when no DB repo is wired (results would have nowhere to
	// land). Failures here degrade — the agent loop still runs.
	prescanCtx := buildPrescanInstruction(ctx, repo, projectUUID)
	mergedInstruction := instruction
	if prescanCtx != "" {
		if mergedInstruction != "" {
			mergedInstruction = mergedInstruction + "\n\n" + prescanCtx
		} else {
			mergedInstruction = prescanCtx
		}
	}

	result, runErr := autopilot.Run(ctx, autopilot.Options{
		Provider:        prov,
		Model:           model,
		ReasoningEffort: settings.Agent.Olium.ReasoningEffort,
		MaxTokens:       settings.Agent.Olium.MaxTokens,
		Target:          autopilotTarget,
		SourcePath:      autopilotSource,
		Focus:           autopilotFocus,
		Instruction:     mergedInstruction,
		ProjectUUID:     projectUUID,
		ScanUUID:        globalScanUUID,
		AgenticScanUUID: parentAgenticScanUUID,
		Repo:            repo,
		ConfigPath:      globalConfig,
		SessionDir:      sessionDir,
		// --max-commands bounds tool calls, which is what it says and what
		// an operator budgets for. The turn ceiling stays as a separate
		// backstop so a model that never calls a tool still terminates.
		MaxToolCalls:      autopilotMaxCommands,
		MaxTurns:          autopilotMaxCommands,
		MaxWallTime:       autopilotMaxDuration,
		TokenBudget:       autopilotTokenBudget,
		MaxCostUSD:        autopilotMaxCostUSD,
		Out:               streamWriter,
		Verbose:           autopilotVerbose,
		SystemPrompt:      effectiveSystemPrompt,
		BrowserAvailable:  settings.Agent.Browser.IsEnabled(),
		BrowserBinaryPath: settings.Agent.Browser.BinaryPath,
		SkillNames:        autopilotSkills,
		SkillTags:         autopilotSkillTags,
		NoSkillFilter:     autopilotNoSkillFilter,
		AlwaysOnSkills:    settings.Agent.Olium.EffectiveAlwaysOnSkills(),
		// Durable-autopilot mode (legacy default). Enables bounded operator
		// sections with context rotation + verify-before-promote when the
		// operator opts in via agent.olium.autopilot_mode.
		Mode: settings.Agent.Olium.EffectiveAutopilotMode(),
	})

	// Durable-autopilot verify-before-promote (direct CLI path). Runs before
	// finalize/summary so their DB-backed finding counts include the promoted
	// findings. No-op in legacy mode (the default). Non-fatal.
	if runErr == nil {
		if apMode := settings.Agent.Olium.EffectiveAutopilotMode(); apMode != config.AutopilotModeLegacy && repo != nil {
			if _, verr := agent.VerifyCandidates(ctx, agent.VerifyCandidatesConfig{
				Repo:            repo,
				Provider:        prov,
				Model:           model,
				ProjectUUID:     projectUUID,
				ScanUUID:        globalScanUUID,
				AgenticScanUUID: parentAgenticScanUUID,
				Target:          autopilotTarget,
				SessionDir:      sessionDir,
				Mode:            apMode,
				StreamWriter:    streamWriter,
			}); verr != nil {
				_, _ = fmt.Fprintf(streamWriter, "[verify] pass failed (findings unaffected): %v\n", verr)
			}
		}
	}

	end := autopilotRunEnd(ctx, runErr, autopilotBudgetStop(result), result.Diagnosis() != "")
	finalizeOliumAutopilotRun(repo, parentAgenticScanUUID, model, startedAt, result, runErr, end)
	walledOut := end.TimedOut
	if walledOut {
		_, _ = fmt.Fprintf(streamWriter, "[autopilot] wall reached after %s — finalizing partial results\n", autopilotMaxDuration)
	}

	if autopilotTriage && end.Err == nil && !walledOut && !end.BudgetExhausted && !end.Cancelled {
		triageEngine := agent.NewEngine(settings, repo)
		if _, terr := agent.RunAutopilotTriage(ctx, triageEngine, repo, agent.AutopilotTriageParams{
			TargetURL:       autopilotTarget,
			SourcePath:      autopilotSource,
			ScanUUID:        globalScanUUID,
			ProjectUUID:     projectUUID,
			AgenticScanUUID: parentAgenticScanUUID,
			SessionDir:      sessionDir,
			StreamWriter:    streamWriter,
			Verbose:         autopilotVerbose,
		}); terr != nil {
			_, _ = fmt.Fprintf(streamWriter, "[triage] failed (scan results unaffected): %v\n", terr)
		}
	}

	outcome.End = end
	if result != nil {
		outcome.HaltReason = result.HaltReason
		outcome.FindingCount = result.FindingCount
		outcome.Usage = agentRunUsage{InputTokens: result.InputTokens, OutputTokens: result.OutputTokens, CostUSD: result.CostUSD}
		outcome.Budget.Stop = result.BudgetStop
		outcome.Budget.Exhausted = end.BudgetExhausted || end.TimedOut
		if d := result.Diagnosis(); d != "" {
			outcome.Warnings = append(outcome.Warnings, d)
		}
	}
	if end.Err != nil {
		outcome.addError(fmt.Errorf("autopilot session failed: %w", end.Err))
	}
	// docErr carries a failed -j document write (or the run's exit-5 result)
	// past the post-run steps below, which still run either way.
	var docErr error
	if globalJSON {
		if err := emitAgentRunDocument(outcome); err != nil && end.Err == nil {
			docErr = err
		}
	} else {
		printOliumAutopilotSummary(result, sessionDir, repo, parentAgenticScanUUID)
	}

	if autopilotUploadResults && end.Err == nil {
		uploadAgenticScanResults(settings, projectUUID, parentAgenticScanUUID, sessionDir, repo)
	}

	webhook.FireAgenticScan(settings, repo, parentAgenticScanUUID)
	copyTranscriptIfRequested(sessionDir, streamWriter)
	if end.Err != nil {
		return fmt.Errorf("autopilot session failed: %w", end.Err)
	}
	if docErr != nil {
		return docErr
	}
	_, jsonStatus := agentRunStatus(end)
	return agentRunExitError(jsonStatus, parentAgenticScanUUID, firstNonEmptyString(outcome.HaltReason, outcome.Budget.Stop))
}

// copyTranscriptIfRequested honors --transcript: after the run, copy the
// session's transcript.jsonl to the requested path so it survives even when the
// caller doesn't want to hunt in the session dir (e.g. a throwaway/stateless DB
// run kept only for debugging). The in-session copy is always kept; any failure
// is non-fatal and surfaced on the stream.
func copyTranscriptIfRequested(sessionDir string, w io.Writer) {
	if autopilotTranscript == "" || sessionDir == "" {
		return
	}
	src := filepath.Join(sessionDir, "transcript.jsonl")
	data, err := os.ReadFile(src)
	if err != nil {
		_, _ = fmt.Fprintf(w, "[transcript] could not read %s: %v\n", src, err)
		return
	}
	if err := os.WriteFile(autopilotTranscript, data, 0o600); err != nil {
		_, _ = fmt.Fprintf(w, "[transcript] could not write %s: %v\n", autopilotTranscript, err)
		return
	}
	_, _ = fmt.Fprintf(w, "[transcript] copied to %s\n", autopilotTranscript)
}

// autopilotBudgetStop is the budget that ended an autopilot run, "" for none.
func autopilotBudgetStop(result *autopilot.Result) string {
	if result == nil {
		return ""
	}
	return result.BudgetStop
}

// autopilotRunEnd classifies a finished autopilot run (direct or pipeline).
// A wall-clock stop — the ctx deadline or the loop's own MaxWallTime — and a
// command/token/cost budget stop are designed terminal states, not failures:
// the operator produced real work up to the limit, so the run is finalized
// and reported (exit 5), never turned into an error. An interrupt is
// "cancelled"; any other error is "failed".
func autopilotRunEnd(ctx context.Context, runErr error, budgetStop string, degraded bool) database.AgenticRunEnd {
	timedOut := isWallTimeout(ctx, runErr) || budgetStop == autopilot.BudgetWallTime
	budget := budgetStop != "" && budgetStop != autopilot.BudgetWallTime
	end := database.AgenticRunEnd{
		TimedOut:        timedOut,
		BudgetExhausted: budget && !timedOut,
		Degraded:        degraded,
	}
	if runErr != nil && !timedOut && !budget {
		end.Err = runErr
		end.Cancelled = errors.Is(ctx.Err(), context.Canceled)
	}
	return end
}

// prescanBudget bounds the native pre-scan to a fraction of the autopilot wall.
// Without a cap the pre-scan runs unbounded (runner.LaunchScan sets no duration)
// and inherits the full session ctx, so a wedged browser spider (the class
// runSpiderWatchdog catches, but whose budget is minutes) consumes the entire
// wall and starves the operator agent with "context deadline exceeded". Capping
// at clamp(wall/3, 30s, mult*4m) guarantees the agent gets the majority of the
// wall even when the pre-scan stalls, while never exceeding the wall itself.
//
// mult scales the ceiling by scan intensity (see prescanBudgetMultiplier):
// balanced doubles the base 4m ceiling and deep quadruples it, so a heavier
// scan gets a proportionally larger native pre-scan. On the default walls
// (balanced 6h, deep 12h) wall/3 always exceeds the ceiling, so the scaled
// ceiling is what the operator actually sees as the pre-scan budget.
func prescanBudget(wall time.Duration, mult int) time.Duration {
	// NB: pkg/cli shadows the builtin min/max with an int-only min (db_list.go),
	// so an explicit clamp is used rather than min/max on time.Duration.
	if mult < 1 {
		mult = 1
	}
	budget := wall / 3
	ceiling := time.Duration(mult) * 4 * time.Minute
	if budget > ceiling {
		budget = ceiling
	}
	if budget < 30*time.Second {
		budget = 30 * time.Second
	}
	if wall > 0 && budget > wall {
		budget = wall
	}
	return budget
}

// prescanBudgetMultiplier scales the pre-scan budget ceiling by scan intensity:
// balanced x2 and deep x4 of the base 4m ceiling; quick (and any unrecognized
// intensity) keeps x1. Heavier intensities warrant a proportionally larger
// native pre-scan before the operator agent takes over.
func prescanBudgetMultiplier(intensity agenttypes.Intensity) int {
	switch intensity {
	case agenttypes.IntensityBalanced:
		return 2
	case agenttypes.IntensityDeep:
		return 4
	default:
		return 1
	}
}

// isWallTimeout reports whether a finished autopilot run stopped because it hit
// its max-duration wall (a graceful, expected terminal state) rather than a real
// failure. It keys off the wall-bounded ctx, NOT runErr: the engine surfaces its
// failure through engine.Event.Err — a plain string field — so the underlying
// error sentinel is already gone before the caller sees runErr, and
// errors.Is(runErr, …) can never match (this is why the run error can't carry
// context.DeadlineExceeded). ctx.Err()==DeadlineExceeded iff the wall fired,
// which correctly excludes a transient per-call provider timeout (wall ctx
// un-fired) and Ctrl-C/SIGTERM (Canceled, not DeadlineExceeded).
func isWallTimeout(ctx context.Context, runErr error) bool {
	return runErr != nil && errors.Is(ctx.Err(), context.DeadlineExceeded)
}

// buildPrescanInstruction launches the autopilot native pre-scan (when
// permitted) and returns a short context blob to splice into the operator
// agent's initial Instruction. Returns "" when the pre-scan is disabled,
// gated, or fails — failure is logged but never aborts the autopilot run,
// since a cold-start operator is still better than no run at all.
//
// Gating (any one suppresses the pre-scan):
//   - --no-prescan flag set
//   - autopilotTarget empty (source-only run; pipeline path already took it)
//   - repo nil (no DB → results would have nowhere to land)
//   - intensity unrecognized (defensive — runAgentAutopilot already validated)
func buildPrescanInstruction(ctx context.Context, repo *database.Repository, projectUUID string) string {
	if autopilotNoPrescan {
		return ""
	}
	if strings.TrimSpace(autopilotTarget) == "" {
		return ""
	}
	if repo == nil {
		return ""
	}
	intensity, err := agenttypes.ValidateIntensity(autopilotIntensity)
	if err != nil {
		return ""
	}
	strategy := agenttypes.AutopilotPresets[intensity].NativeScanStrategy
	if strategy == "" {
		return ""
	}

	preScanBudget := prescanBudget(autopilotMaxDuration, prescanBudgetMultiplier(intensity))

	fmt.Fprintf(os.Stderr, "%s Pre-scan: %s strategy against %s (native scan: discover + dynamic-assessment; budget %s)\n",
		terminal.InfoSymbol(),
		terminal.Cyan(strategy),
		terminal.Cyan(autopilotTarget),
		terminal.Cyan(preScanBudget.Round(time.Second).String()))

	// Browser spidering is intentionally OFF for the pre-scan. It is the slow,
	// wedge-prone phase: on a real target it can hang the browser (abandoned by
	// runSpiderWatchdog, leaking a Chrome that then contends with the operator
	// agent's own agent-browser). Discovery + dynamic-assessment seed plenty of
	// http_records/findings fast, and the operator agent does its own browser
	// exploration — so the pre-scan gains little from spidering and pays a lot.
	params := runner.LaunchParams{
		Targets:          []string{autopilotTarget},
		ProjectUUID:      projectUUID,
		ConfigPath:       globalConfig,
		Repository:       repo,
		ScanningStrategy: strategy,
		EnableDiscovery:  true,
		EnableSpidering:  false,
		ScanMaxDuration:  preScanBudget,
		AuthFiles:        autopilotAuthFiles,
	}
	res, err := runner.LaunchScan(ctx, params)
	if err != nil {
		uuid := ""
		if res != nil {
			uuid = res.ScanUUID
		}
		fmt.Fprintf(os.Stderr, "%s Pre-scan failed (uuid=%s): %v — continuing without it\n",
			terminal.WarningSymbol(), uuid, err)
		return ""
	}
	if res == nil {
		return ""
	}

	fmt.Fprintf(os.Stderr, "%s Pre-scan complete: scan=%s requests=%d findings=%d (%s)\n",
		terminal.SuccessSymbol(),
		terminal.Muted(res.ScanUUID),
		res.TotalRequests, res.FindingCount,
		(time.Duration(res.DurationMs) * time.Millisecond).Round(time.Second))

	out := formatPrescanContext(res)
	if sample := samplePrescanRecords(ctx, repo, res.ScanUUID, 10); sample != "" {
		out += "\n\n" + sample
	}
	return out
}

// samplePrescanRecords returns a short markdown table of up to limit HTTP
// records produced by the prescan, picked by ordering distinct hostnames and
// method/path tuples to maximize endpoint variety. Returns "" when the query
// fails, finds nothing, or repo is nil — the caller treats that as "no
// sample available" and still emits the base brief.
//
// Why: surfaces real endpoints to the agent so it can reason about coverage
// gaps without having to issue extra tool calls just to learn what was found.
func samplePrescanRecords(ctx context.Context, repo *database.Repository, scanUUID string, limit int) string {
	if repo == nil || scanUUID == "" || limit <= 0 {
		return ""
	}
	var rows []struct {
		Method     string `bun:"method"`
		URL        string `bun:"url"`
		StatusCode int    `bun:"status_code"`
		Path       string `bun:"path"`
	}
	err := repo.DB().NewSelect().
		Table("http_records").
		Column("method", "url", "status_code", "path").
		Where("scan_uuid = ?", scanUUID).
		Order("status_code DESC", "length(path) ASC").
		Limit(int64(limit)).
		Scan(ctx, &rows)
	if err != nil || len(rows) == 0 {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "**Sample endpoints (%d of %d):**\n\n", len(rows), limit)
	b.WriteString("| Method | Status | URL |\n")
	b.WriteString("|---|---|---|\n")
	for _, r := range rows {
		fmt.Fprintf(&b, "| %s | %d | %s |\n", r.Method, r.StatusCode, r.URL)
	}
	return strings.TrimRight(b.String(), "\n")
}

// formatPrescanContext renders the pre-scan result as a short markdown
// blob the agent can chew on. Surfaces the scan UUID + counts so it can
// pull structured data via list_findings / list_sessions / traffic tools.
func formatPrescanContext(res *runner.LaunchResult) string {
	var b strings.Builder
	b.WriteString("**Pre-scan context:** a native vigolium scan already ran against this target.\n")
	fmt.Fprintf(&b, "- scan_uuid: %s\n", res.ScanUUID)
	fmt.Fprintf(&b, "- http_records collected: %d\n", res.TotalRequests)
	fmt.Fprintf(&b, "- findings: %d total (critical=%d high=%d medium=%d low=%d info=%d suspect=%d)\n",
		res.FindingCount, res.Critical, res.High, res.Medium, res.Low, res.Info, res.Suspect)
	b.WriteString("\nUse `list_findings` (filter by scan_uuid) and the traffic tools to inspect the recorded ")
	b.WriteString("requests and findings before launching new probes. Treat this scan as the dynamic baseline; ")
	b.WriteString("focus your effort on novel coverage and correlation-based bugs (write a JS extension via ")
	b.WriteString("`run_extension` when the bug class needs cross-record analysis).")
	return b.String()
}

// resolveAutopilotAuditCfg picks which audit harness to drive based on the
// CLI globals already resolved by runAgentAutopilot's auto-pick. Returns
// (nil, zero-spec) when no audit should run (no source, or both flags off).
func resolveAutopilotAuditCfg(settings *config.Settings) (*config.AuditAgentConfig, agent.HarnessSpec) {
	noAudit := autopilotAudit == "off"
	auditModeLocal := autopilotAudit
	if noAudit {
		auditModeLocal = ""
	}
	return agent.PickAuditHarness(autopilotPiolium, auditModeLocal, noAudit, autopilotSource, settings.Agent.Audit)
}

// autopilotDryRunView is the `agent autopilot --dry-run` document.
type autopilotDryRunView struct {
	Target        string `json:"target,omitempty"`
	SourcePath    string `json:"source_path,omitempty"`
	Focus         string `json:"focus,omitempty"`
	SystemPrompt  string `json:"system_prompt"`
	InitialPrompt string `json:"initial_prompt"`
	Note          string `json:"note"`
}

// printAutopilotDryRun renders the operator's system prompt and first turn
// offline. The provider is not resolved, so a provider-specific persona
// (claude-code) is not reflected; the prior-context, knowledge-base and
// pre-scan sections a live run appends are left out because building them
// reads the store, calls the model or scans the target.
func printAutopilotDryRun(cmd *cobra.Command, settings *config.Settings, instruction string) error {
	systemPrompt, err := resolveSystemPrompt(autopilotSystemPrompt, autopilotSystemPromptFile)
	if err != nil {
		return err
	}
	system, initial := autopilot.RenderPrompts(autopilot.Options{
		Target:       autopilotTarget,
		SourcePath:   autopilotSource,
		Focus:        autopilotFocus,
		Instruction:  instruction,
		SystemPrompt: firstNonEmptyString(systemPrompt, settings.Agent.Olium.SystemPrompt),
		// Autopilot always runs with the browser (runAutopilotOlium forces it).
		BrowserAvailable: true,
	})
	view := autopilotDryRunView{
		Target: autopilotTarget, SourcePath: autopilotSource, Focus: autopilotFocus,
		SystemPrompt: system, InitialPrompt: initial,
		Note: "dry run: nothing was sent and no provider was called; a live run also appends prior-context, knowledge-base and pre-scan sections to the first turn",
	}
	if globalJSON {
		return emitObject(cmd, ".", view)
	}
	fmt.Printf("── system prompt ──\n%s\n\n── first turn ──\n%s\n\n", system, initial)
	fmt.Fprintf(os.Stderr, "%s %s\n", terminal.InfoSymbol(), view.Note)
	return nil
}

// runAutopilotOliumPipeline drives the autopilot pipeline runner — the same path
// the server uses for `POST /api/agent/run/autopilot`. Used when an audit
// (audit or piolium) should run before the operator agent. Token tracking
// and TokenBudget enforcement are not yet plumbed through the pipeline
// runner; the parent context timeout still applies.
func runAutopilotOliumPipeline(
	ctx context.Context,
	settings *config.Settings,
	repo *database.Repository,
	instruction string,
	auditCfg *config.AuditAgentConfig,
	harness agent.HarnessSpec,
	outcome *agentRunOutcome,
	streamWriter io.Writer,
) error {
	sessionDir, projectUUID, parentAgenticScanUUID := outcome.SessionDir, outcome.ProjectUUID, outcome.AgenticScanUUID
	startedAt := outcome.StartedAt
	systemPrompt, sysErr := resolveSystemPrompt(autopilotSystemPrompt, autopilotSystemPromptFile)
	if sysErr != nil {
		return sysErr
	}
	cfg := agent.AutopilotPipelineConfig{
		TargetURL:             autopilotTarget,
		SourcePath:            autopilotSource,
		Files:                 autopilotFiles,
		Instruction:           instruction,
		Focus:                 autopilotFocus,
		SkillNames:            autopilotSkills,
		SkillTags:             autopilotSkillTags,
		NoSkillFilter:         autopilotNoSkillFilter,
		AlwaysOnSkills:        settings.Agent.Olium.EffectiveAlwaysOnSkills(),
		SystemPrompt:          systemPrompt,
		AgentName:             "olium",
		MaxCommands:           autopilotMaxCommands,
		TokenBudget:           autopilotTokenBudget,
		MaxCostUSD:            autopilotMaxCostUSD,
		SkipPreflight:         autopilotPreflight.skip,
		DryRun:                autopilotDryRun,
		ShowPrompt:            autopilotShowPrompt,
		Triage:                autopilotTriage,
		SessionsDir:           settings.Agent.EffectiveSessionsDir(),
		SessionDir:            sessionDir,
		ProjectUUID:           projectUUID,
		ScanUUID:              globalScanUUID,
		ParentAgenticScanUUID: parentAgenticScanUUID,
		StreamWriter:          streamWriter,
		Audit:                 auditCfg,
		AuditHarness:          harness,
		BrowserEnabled:        settings.Agent.Browser.IsEnabled(),
		BrowserBinaryPath:     settings.Agent.Browser.BinaryPath,
		BrowserRequested:      autopilotRequiresBrowser,
		RequiresBrowser:       autopilotRequiresBrowser,
		// Browser is always-on for autopilot (runAutopilotOlium forces
		// agent.browser.enable), so keep the tool available even when the pipeline
		// runner's decideBrowserUsage heuristic returns browser_unneeded for a
		// plain UI/DOM-XSS prompt. This guards only tool availability — it does not
		// flag explicit intent, so the browser-auth preflight stays gated on real
		// credentials / RequiresBrowser.
		KeepBrowserEnabled:   settings.Agent.Browser.IsEnabled(),
		Credentials:          autopilotCredentials,
		AuthRequired:         autopilotAuthRequired,
		BrowserStartURL:      autopilotBrowserStartURL,
		FocusRoutes:          append([]string(nil), autopilotFocusRoutes...),
		PreflightDiscovery:   !autopilotNoPreflight,
		PostHaltVerify:       !autopilotNoPostHaltVerify,
		PostHaltGapThreshold: autopilotPostHaltGap,
	}

	engine := agent.NewEngine(settings, repo)
	runner := agent.NewAutopilotPipelineRunner(engine, repo)
	result, runErr := runner.RunAutonomous(ctx, cfg)

	var budgetStop string
	degraded := false
	if result != nil {
		budgetStop = result.BudgetStop
		degraded = result.Degraded
	}
	end := autopilotRunEnd(ctx, runErr, budgetStop, degraded)
	finalizeOliumAutopilotPipelineRun(repo, parentAgenticScanUUID, startedAt, result, runErr, end)
	if end.TimedOut {
		_, _ = fmt.Fprintf(streamWriter, "[autopilot] wall reached after %s — finalizing partial results\n", autopilotMaxDuration)
	}

	outcome.End = end
	outcome.Budget.Stop = budgetStop
	outcome.Budget.Exhausted = end.BudgetExhausted || end.TimedOut
	if result != nil {
		outcome.FindingCount = int64(max(result.FindingsCount, result.OperatorFindingsCount, result.VerifiedFindingCount))
		outcome.Usage = agentRunUsage{InputTokens: result.InputTokens, OutputTokens: result.OutputTokens, CostUSD: result.CostUSD}
		outcome.Warnings = append(outcome.Warnings, result.Warnings...)
	}
	if end.Err != nil {
		outcome.addError(fmt.Errorf("autopilot session failed: %w", end.Err))
	}
	if globalJSON {
		if docErr := emitAgentRunDocument(outcome); docErr != nil && end.Err == nil {
			return docErr
		}
	} else {
		printOliumAutopilotPipelineSummary(result, sessionDir, repo, parentAgenticScanUUID)
	}

	if autopilotUploadResults && end.Err == nil {
		uploadAgenticScanResults(settings, projectUUID, parentAgenticScanUUID, sessionDir, repo)
	}

	webhook.FireAgenticScan(settings, repo, parentAgenticScanUUID)
	if end.Err != nil {
		return fmt.Errorf("autopilot session failed: %w", end.Err)
	}
	_, jsonStatus := agentRunStatus(end)
	return agentRunExitError(jsonStatus, parentAgenticScanUUID, budgetStop)
}

// finalizeOliumAutopilotPipelineRun closes out the parent AgenticScan row when
// the run went through the pipeline runner. The pipeline result exposes
// audit/operator/verified finding counts but not per-call token usage, so the
// finding_count column reflects the highest-fidelity available number.
func finalizeOliumAutopilotPipelineRun(repo *database.Repository, agenticScanUUID string, startedAt time.Time, result *agent.AutopilotPipelineResult, runErr error, end database.AgenticRunEnd) {
	if repo == nil || agenticScanUUID == "" {
		return
	}
	completedAt := time.Now()
	status, _ := agentRunStatus(end)

	q := repo.DB().NewUpdate().Model((*database.AgenticScan)(nil)).
		Set("status = ?", status).
		Set("completed_at = ?", completedAt).
		Set("duration_ms = ?", completedAt.Sub(startedAt).Milliseconds()).
		Where("uuid = ?", agenticScanUUID)

	if result != nil {
		findingCount := result.FindingsCount
		if result.VerifiedFindingCount > 0 {
			findingCount = result.VerifiedFindingCount
		} else if result.OperatorFindingsCount > findingCount {
			findingCount = result.OperatorFindingsCount
		}
		q = q.Set("finding_count = ?", findingCount)
	}
	if runErr != nil {
		q = q.Set("error_message = ?", runErr.Error())
	} else if result != nil && len(result.Warnings) > 0 {
		q = q.Set("error_message = ?", strings.Join(result.Warnings, "\n"))
	}
	if _, err := q.Exec(context.Background()); err != nil {
		zap.L().Debug("Failed to finalize autopilot pipeline run", zap.Error(err))
	}
}

// printOliumAutopilotPipelineSummary mirrors printOliumAutopilotSummary's shape
// but pulls fields from the pipeline result (which has separate counts for
// audit, operator, and verified findings).
func printOliumAutopilotPipelineSummary(result *agent.AutopilotPipelineResult, sessionDir string, repo *database.Repository, agenticScanUUID string) {
	if result == nil {
		return
	}
	fmt.Println()
	fmt.Printf("%s autopilot complete\n", terminal.InfoSymbol())
	// Compute the severity breakdown once — the run wrote into one
	// agentic_scan_uuid bucket, so the same suffix annotates whichever
	// of audit/operator/verified is the canonical headline number.
	_, breakdown, _ := findingCountForRun(repo, agenticScanUUID)
	headlineShown := false
	if result.FindingsCount > 0 {
		fmt.Printf("  audit:    %s findings (saved: %d)%s\n",
			terminal.BoldGreen(fmt.Sprintf("%d", result.FindingsCount)),
			result.FindingsSaved,
			breakdown)
		headlineShown = true
	}
	if result.OperatorFindingsCount > 0 {
		// Only attach the breakdown to the highest-fidelity line so the
		// same per-severity counts don't repeat under multiple headers.
		suffix := ""
		if !headlineShown {
			suffix = breakdown
		}
		fmt.Printf("  operator:  %s findings%s\n",
			terminal.BoldGreen(fmt.Sprintf("%d", result.OperatorFindingsCount)),
			suffix)
		headlineShown = true
	}
	if result.VerifiedFindingCount > 0 {
		suffix := ""
		if !headlineShown {
			suffix = breakdown
		}
		fmt.Printf("  verified:  %s%s\n",
			terminal.BoldGreen(fmt.Sprintf("%d", result.VerifiedFindingCount)),
			suffix)
	}
	fmt.Printf("  duration:  %s\n", result.Duration.Round(time.Second))
	if result.Reentries > 0 {
		fmt.Printf("  re-entry:  %s\n",
			terminal.Muted(fmt.Sprintf("%d coverage-verify re-prompt(s)", result.Reentries)))
	}
	if result.Degraded {
		fmt.Printf("  status:    %s\n", terminal.Muted("degraded — see warnings"))
	}
	if sessionDir != "" {
		fmt.Printf("  session:   %s\n", terminal.Muted(terminal.ShortenHome(sessionDir)))
	}
}

// finalizeOliumAutopilotRun closes out the parent AgenticScan row with
// the run's final state. Done as a field-level UPDATE so we don't clobber
// other columns that were set at CreateAgenticScan time.
func finalizeOliumAutopilotRun(repo *database.Repository, agenticScanUUID, model string, startedAt time.Time, result *autopilot.Result, runErr error, end database.AgenticRunEnd) {
	if repo == nil || agenticScanUUID == "" {
		return
	}
	completedAt := time.Now()
	diagnosis := result.Diagnosis() // nil-safe
	status, _ := agentRunStatus(end)

	q := repo.DB().NewUpdate().Model((*database.AgenticScan)(nil)).
		Set("status = ?", status).
		Set("completed_at = ?", completedAt).
		Set("duration_ms = ?", completedAt.Sub(startedAt).Milliseconds()).
		Where("uuid = ?", agenticScanUUID)
	if result != nil {
		q = q.Set("finding_count = ?", result.FindingCount)
		// Persist token usage and estimated cost — the engine emits
		// per-turn usage events that autopilot.Run accumulates; without
		// this update the row defaults to 0/0/$0 even on real runs.
		usage := claudecost.Usage{
			InputTokens:       result.InputTokens,
			OutputTokens:      result.OutputTokens,
			CacheReadTokens:   result.CacheReadTokens,
			CacheCreateTokens: result.CacheCreateTokens,
		}
		q = q.Set("total_input_tokens = ?", result.InputTokens).
			Set("total_output_tokens = ?", result.OutputTokens).
			Set("estimated_cost_usd = ?", usage.Price(model))
		// Mirror the swarm path: write a single rollup entry into the
		// JSONB column so the existing per-phase renderer surfaces
		// totals as well. Autopilot doesn't have phases, so one entry.
		if result.InputTokens > 0 || result.OutputTokens > 0 {
			q = q.Set("token_usage = ?", map[string]interface{}{
				"autopilot": map[string]interface{}{
					"input_tokens":  result.InputTokens,
					"output_tokens": result.OutputTokens,
				},
			})
		}
	}
	if runErr != nil {
		q = q.Set("error_message = ?", runErr.Error())
	} else if diagnosis != "" {
		q = q.Set("error_message = ?", diagnosis)
	}
	if _, err := q.Exec(context.Background()); err != nil {
		zap.L().Debug("Failed to finalize autopilot parent run", zap.Error(err))
	}
}

// autopilotBannerInputs collects the values the startup banner renders.
// Keeping this as a single struct keeps the call site readable and makes
// future additions (token budget, focus, instruction) a one-line change
// instead of a function-signature churn.
type autopilotBannerInputs struct {
	Provider        string
	Model           string
	ProjectUUID     string
	Target          string
	SourcePath      string
	Intensity       string
	MaxCommands     int
	MaxDuration     time.Duration
	AuditDriverMode string
	PioliumMode     string
	BrowserEnabled  bool
	NoPrescan       bool
	SessionDir      string
	AgenticScanUUID string
}

// printAutopilotBanner renders a configuration summary mirroring the
// `Native Scan Configuration` banner emitted by `vigolium scan`, so the
// two surfaces look like the same product when an operator switches
// between them.
func printAutopilotBanner(in autopilotBannerInputs) {
	w := os.Stderr
	_, _ = fmt.Fprintf(w, "%s %s\n",
		terminal.Green(terminal.SymbolStart),
		terminal.BoldHiBlue("Autopilot Configuration"))

	_, _ = fmt.Fprintf(w, "  %s Provider: %s | Model: %s\n",
		terminal.Purple(terminal.SymbolInfo),
		terminal.Orange(clicommon.ValueOrNone(in.Provider)),
		terminal.Orange(clicommon.ValueOrNone(in.Model)))

	if in.ProjectUUID != "" {
		_, _ = fmt.Fprintf(w, "  %s Project: %s\n",
			terminal.Purple(terminal.SymbolInfo),
			terminal.HiTeal(in.ProjectUUID))
	}

	if in.Target != "" {
		_, _ = fmt.Fprintf(w, "  %s Target: %s\n",
			terminal.Purple(terminal.SymbolTarget),
			terminal.HiBlue(in.Target))
	}
	if in.SourcePath != "" {
		_, _ = fmt.Fprintf(w, "  %s Source: %s\n",
			terminal.Purple(terminal.SymbolInfo),
			terminal.HiTeal(terminal.ShortenHome(in.SourcePath)))
	}

	// Intensity + budgets on a single line so the operator sees the
	// effective wall-clock and tool-call caps without scanning two rows.
	budgetParts := []string{}
	if in.MaxCommands > 0 {
		budgetParts = append(budgetParts, fmt.Sprintf("max-cmds=%s",
			terminal.HiBlue(fmt.Sprintf("%d", in.MaxCommands))))
	}
	if in.MaxDuration > 0 {
		budgetParts = append(budgetParts, fmt.Sprintf("wall=%s",
			terminal.HiBlue(in.MaxDuration.String())))
	}
	intensityLine := terminal.HiTeal(clicommon.ValueOrNone(in.Intensity))
	if len(budgetParts) > 0 {
		intensityLine += " " + terminal.Muted("("+strings.Join(budgetParts, " | ")+")")
	}
	_, _ = fmt.Fprintf(w, "  %s Intensity: %s\n",
		terminal.Purple(terminal.SymbolInfo), intensityLine)

	// Audit: audit / piolium modes side by side. Only surfaced when
	// --source is set, since the audit harness is a whitebox-only step
	// (target-only runs use the native pre-scan path instead). "off"
	// shows explicitly when source is set so it's obvious neither
	// harness will run before the operator.
	if in.SourcePath != "" {
		auditShown := in.AuditDriverMode
		if auditShown == "" {
			auditShown = "off"
		}
		pioliumShown := in.PioliumMode
		if pioliumShown == "" {
			pioliumShown = "off"
		}
		_, _ = fmt.Fprintf(w, "  %s Audit: audit=%s | piolium=%s\n",
			terminal.Purple(terminal.SymbolInfo),
			terminal.Orange(auditShown),
			terminal.Orange(pioliumShown))
	}

	// Browser + pre-scan. Pre-scan is the full native scan (discover + spider +
	// dynamic-assessment) seed that only fires on target-only runs; n/a when
	// --source is set because the audit harness replaces that role.
	browserShown := "disabled"
	if in.BrowserEnabled {
		browserShown = "enabled"
	}
	var prescanShown string
	switch {
	case in.SourcePath != "":
		prescanShown = "n/a (audit replaces)"
	case in.NoPrescan:
		prescanShown = "disabled"
	default:
		prescanShown = "enabled"
	}
	_, _ = fmt.Fprintf(w, "  %s Browser: %s | Pre-scan: %s\n",
		terminal.Purple(terminal.SymbolInfo),
		terminal.Orange(browserShown),
		terminal.Orange(prescanShown))

	if in.SessionDir != "" {
		_, _ = fmt.Fprintf(w, "  %s Session: %s\n",
			terminal.Purple(terminal.SymbolInfo),
			terminal.Muted(terminal.ShortenHome(in.SessionDir)))
		_, _ = fmt.Fprintf(w, "  %s Transcript: %s\n",
			terminal.Purple(terminal.SymbolInfo),
			terminal.Muted(terminal.ShortenHome(filepath.Join(in.SessionDir, transcriptFilename))))
	}

	if in.AgenticScanUUID != "" {
		_, _ = fmt.Fprintf(w, "  %s %s %s\n",
			terminal.Yellow(terminal.SymbolDiamond),
			terminal.Gray("tail logs with"),
			terminal.HiCyan(fmt.Sprintf("vigolium log %s", in.AgenticScanUUID)))
	}
	_, _ = fmt.Fprintln(w)
}

// printOliumAutopilotSummary renders a concise operator-facing summary
// of how the run went. Mirrors printAutopilotSummary's shape so the
// two modes look the same in a terminal.
func printOliumAutopilotSummary(result *autopilot.Result, sessionDir string, repo *database.Repository, agenticScanUUID string) {
	if result == nil {
		return
	}
	// Headline count from the DB reflects every finding persisted for this
	// run (operator report_finding + audit-prep imports), not just the
	// operator's runtime counter. ok=false on dry-run / no-repo paths.
	total, breakdown, ok := findingCountForRun(repo, agenticScanUUID)
	if !ok {
		total = result.FindingCount
	}
	fmt.Println()
	fmt.Printf("%s autopilot complete\n", terminal.InfoSymbol())
	// Labels padded to a 12-char field so the longest ("transcript:") still
	// leaves a space before its value and the whole column stays aligned.
	fmt.Printf("  findings:   %s%s\n",
		terminal.BoldGreen(fmt.Sprintf("%d", total)),
		breakdown)
	fmt.Printf("  duration:   %s\n", result.Elapsed.Round(time.Second))
	switch d := result.Diagnosis(); {
	case result.Halted:
		fmt.Printf("  halt:       %s\n", result.HaltReason)
	case d != "":
		fmt.Printf("  halt:       %s\n", terminal.Yellow(d))
	default:
		fmt.Printf("  halt:       %s\n", terminal.Muted("(natural stop - no more tool calls)"))
	}
	if result.Reentries > 0 {
		fmt.Printf("  re-entry:   %s\n",
			terminal.Muted(fmt.Sprintf("%d coverage-verify re-prompt(s)", result.Reentries)))
	}
	if sessionDir != "" {
		fmt.Printf("  session:    %s\n", terminal.Muted(terminal.ShortenHome(sessionDir)))
		// Re-surface the transcript path at the end so it's easy to grab for
		// post-hoc review without scrolling back to the startup banner.
		fmt.Printf("  transcript: %s\n",
			terminal.Muted(terminal.ShortenHome(filepath.Join(sessionDir, transcriptFilename))))
	}
	// Point at the session log so it's one command away — `vigolium log <id>`
	// renders the transcript as a conversation replay (add --raw for JSONL).
	if agenticScanUUID != "" {
		fmt.Printf("  %s %s %s\n",
			terminal.Yellow(terminal.SymbolDiamond),
			terminal.Gray("replay session with"),
			terminal.HiCyan(fmt.Sprintf("vigolium log %s", agenticScanUUID)))
	}
}

// severityColors maps canonical severity names to their display palette.
// Names are sourced from severity.AllNames() so adding a new severity in
// pkg/types/severity automatically extends the breakdown render once a
// matching color is registered here; missing entries fall back to muted.
var severityColors = map[string]func(string) string{
	"critical": terminal.BoldMagenta,
	"high":     terminal.BoldRed,
	"medium":   terminal.BoldYellow,
	"low":      terminal.BoldGreen,
	"info":     terminal.BoldBlue,
	"suspect":  terminal.BoldCyan,
}

// findingCountForRun returns the total findings persisted under the run's
// agentic_scan_uuid, a colored `(critical=N high=M …)` suffix, and ok=true
// when the count came from the DB. ok=false signals the caller to fall back
// to its own runtime counter (dry-run / no-repo / query error paths).
// Zero-count severities are omitted from the suffix.
func findingCountForRun(repo *database.Repository, agenticScanUUID string) (int64, string, bool) {
	if repo == nil || agenticScanUUID == "" {
		return 0, "", false
	}
	counts, err := database.CountFindingsByAgenticScan(context.Background(), repo.DB(), agenticScanUUID)
	if err != nil {
		return 0, "", false
	}
	var total int64
	for _, n := range counts {
		total += n
	}
	// Render most-severe-first; AllNames() is least-to-most-severe.
	names := severity.AllNames()
	parts := make([]string, 0, len(names))
	for i := len(names) - 1; i >= 0; i-- {
		key := names[i]
		n := counts[key]
		if n == 0 {
			continue
		}
		color := severityColors[key]
		if color == nil {
			color = terminal.Muted
		}
		parts = append(parts, fmt.Sprintf("%s=%s",
			terminal.Muted(key),
			color(fmt.Sprintf("%d", n))))
	}
	if len(parts) == 0 {
		return total, "", true
	}
	return total, "  " + terminal.Muted("(") + strings.Join(parts, " ") + terminal.Muted(")"), true
}
