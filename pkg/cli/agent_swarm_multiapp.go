package cli

// Multi-app swarm orchestration: fanning a single swarm invocation out across
// several discovered apps. Split out of agent_swarm.go to keep that file on the
// single-app path; the shared helpers (runPhaseRunner, summarizeModules) remain
// there.

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/agent"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/vigolium/vigolium/pkg/types"
)

// runMultiAppSwarm fans out parallel swarm runs for multiple apps.
func runMultiAppSwarm(ctx context.Context, cmd *cobra.Command, engine *agent.Engine, settings *config.Settings, repo *database.Repository, intent *agent.ScanIntent) error {
	if swarmMaxDuration > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, swarmMaxDuration)
		defer cancel()
	}

	return runMultiAppFanOut(ctx, intent, func(ctx context.Context, idx int, app agent.AppIntent) error {
		agenticScanUUID := uuid.New().String()
		sessionDir, _ := agent.EnsureSessionDir(settings.Agent.EffectiveSessionsDir(), agenticScanUUID)

		instruction := mergeIntentInstruction(swarmInstruction, swarmInstructionFile, app)
		instruction = prependVerbatimPrompt(instruction, swarmInstructionPrefix)
		focus := swarmFocus
		if app.Focus != "" {
			focus = app.Focus
		}
		vulnType := swarmVulnType
		if focus != "" && vulnType == "" {
			vulnType = focus
		}

		fmt.Fprintf(os.Stderr, "%s [%d/%d] Starting swarm: target=%s source=%s\n",
			terminal.InfoSymbol(), idx+1, len(intent.Apps),
			clicommon.ValueOrNone(app.Target),
			clicommon.ValueOrNone(terminal.ShortenHome(app.SourcePath)))

		var inputs []string
		if app.Target != "" {
			inputs = append(inputs, app.Target)
		}

		codeAudit := swarmCodeAudit
		if app.SourcePath != "" && !cmd.Flags().Changed("code-audit") {
			codeAudit = true
		}

		projectUUID, _ := resolveProjectUUID()

		skipPhases := append([]string(nil), swarmSkipPhases...)
		if !swarmTriage && !agent.PhaseSkipped(skipPhases, agent.SwarmPhaseTriage) {
			skipPhases = append(skipPhases, agent.SwarmPhaseTriage)
		}

		var generatedAuthConfig string

		phaseCfg := swarmNativePhaseConfig{
			Target:      app.Target,
			ProjectUUID: projectUUID,
			ScanUUID:    globalScanUUID,
			ConfigPath:  globalConfig,
			Verbose:     globalVerbose,
		}

		cfg := agent.SwarmConfig{
			Inputs:          inputs,
			Instruction:     instruction,
			SourcePath:      app.SourcePath,
			VulnType:        vulnType,
			Focus:           focus,
			MaxIterations:   swarmMaxIterations,
			AgentName:       swarmAgentLabel,
			ShowPrompt:      swarmShowPrompt,
			CodeAudit:       codeAudit,
			ForceExtensions: swarmForceExtensions,
			Browser:         swarmBrowser || app.Browser || app.RequiresBrowser,
			Auth:            swarmBrowserAuth || app.RequiresBrowser,
			Credentials: func() string {
				if app.Credentials != "" {
					return app.Credentials
				}
				return swarmCredentials
			}(),
			CredentialSets: func() []agent.IntentCredentialSet {
				if len(app.CredentialSets) > 0 {
					return append([]agent.IntentCredentialSet(nil), app.CredentialSets...)
				}
				return append([]agent.IntentCredentialSet(nil), swarmCredentialSets...)
			}(),
			AuthRequired: func() bool {
				return swarmBrowserAuthRequired || app.AuthRequired || app.RequiresBrowser || app.Credentials != "" || len(app.CredentialSets) > 0
			}(),
			RequiresBrowser: func() bool {
				return swarmRequiresBrowser || app.RequiresBrowser
			}(),
			BrowserStartURL: func() string {
				if app.BrowserStartURL != "" {
					return app.BrowserStartURL
				}
				return swarmBrowserStartURL
			}(),
			FocusRoutes: func() []string {
				if len(app.FocusRoutes) > 0 {
					return append([]string(nil), app.FocusRoutes...)
				}
				return append([]string(nil), swarmFocusRoutes...)
			}(),
			SkipPhases:      skipPhases,
			SessionsDir:     settings.Agent.EffectiveSessionsDir(),
			SessionDir:      sessionDir,
			AgenticScanUUID: agenticScanUUID,
			ProjectUUID:     projectUUID,
			ScanUUID:        globalScanUUID,
		}

		// Wire scan callback using per-app target (not the package-level swarmTarget)
		cfg.ScanFunc = buildMultiAppSwarmScanFunc(settings, repo, phaseCfg, swarmOnlyPhase, swarmSkipPhases, &generatedAuthConfig)

		// Same wiring as the single-app path: browser-auth output should
		// feed the discovery + scan funcs.
		cfg.BrowserAuthCallback = newBrowserAuthCallback(&generatedAuthConfig, app.Target)

		if app.Discover && app.Target != "" {
			cfg.DiscoverFunc = buildMultiAppSwarmDiscoverFunc(settings, repo, phaseCfg, &generatedAuthConfig)
		}

		swarmRunner := agent.NewSwarmRunner(engine, repo)
		_, runErr := swarmRunner.Run(ctx, cfg)
		return runErr
	})
}

// buildMultiAppSwarmScanFunc is like buildAgentSwarmScanFunc but takes an explicit
// per-run phase config instead of relying on package-level CLI globals.
// This is necessary for multi-app fan-out where each goroutine has a different target.
func buildMultiAppSwarmScanFunc(settings *config.Settings, repo *database.Repository, phaseCfg swarmNativePhaseConfig, onlyPhase string, skipPhases []string, authConfigPath *string) agent.ScanFunc {
	return func(ctx context.Context, req agent.ScanRequest) error {
		opts := types.DefaultOptions()
		opts.Targets = []string{phaseCfg.Target}
		opts.ScanUUID = phaseCfg.ScanUUID
		opts.ProjectUUID = phaseCfg.ProjectUUID
		opts.ConfigPath = phaseCfg.ConfigPath
		opts.HeuristicsCheck = "none"
		opts.PassiveModules = []string{"all"}

		if authConfigPath != nil && *authConfigPath != "" {
			opts.AuthFiles = []string{*authConfigPath}
			opts.AuthBestEffort = true
		}

		if req.IsRescan {
			opts.OnlyPhase = "dynamic-assessment"
			opts.SkipIngestion = true
			opts.Modules = agent.ResolveModulesFromPlan(req.ModuleTags, req.ModuleIDs)
		} else {
			opts.Modules = agent.ResolveModulesFromPlan(req.ModuleTags, req.ModuleIDs)
			if len(opts.Modules) == 0 {
				opts.Modules = []string{"all"}
			}
			if onlyPhase != "" {
				opts.OnlyPhase = onlyPhase
			}
			if len(skipPhases) > 0 {
				opts.SkipPhases = skipPhases
			}
		}

		opts.Verbose = phaseCfg.Verbose

		settingsCopy := *settings
		mergeAgentExtensionDir(&settingsCopy.DynamicAssessment.Extensions, req.ExtensionDir)

		fmt.Fprintf(os.Stderr, "%s Scanning %s with modules: %s\n",
			terminal.GrbRed(terminal.SymbolSparkle), phaseCfg.Target,
			summarizeModules(opts.Modules))

		scanRunner, runErr := runner.New(opts)
		if runErr != nil {
			return runErr
		}
		defer scanRunner.Close()

		scanRunner.SetSettings(&settingsCopy)
		scanRunner.SetRepository(repo)
		return scanRunner.RunNativeScan()
	}
}

// buildMultiAppSwarmDiscoverFunc is like buildSwarmDiscoverFunc but takes an explicit
// per-run phase config instead of relying on package-level CLI globals.
func buildMultiAppSwarmDiscoverFunc(settings *config.Settings, repo *database.Repository, phaseCfg swarmNativePhaseConfig, authConfigPath *string) func(ctx context.Context) error {
	return func(ctx context.Context) error {
		if strings.TrimSpace(phaseCfg.Target) == "" {
			fmt.Fprintf(os.Stderr, "%s Discovery skipped: no target URL resolved from input\n",
				terminal.WarningSymbol())
			return nil
		}
		opts := types.DefaultOptions()
		opts.Targets = []string{phaseCfg.Target}
		opts.ScanUUID = phaseCfg.ScanUUID
		opts.ProjectUUID = phaseCfg.ProjectUUID
		opts.ConfigPath = phaseCfg.ConfigPath
		opts.HeuristicsCheck = "none"
		opts.Silent = true
		opts.ScanConfigPrinted = true

		if authConfigPath != nil && *authConfigPath != "" {
			opts.AuthFiles = []string{*authConfigPath}
			opts.AuthBestEffort = true
		}

		fmt.Fprintf(os.Stderr, "%s Discovery+spidering for %s (crawl, JS analysis, external harvesting)\n",
			terminal.GrbRed(terminal.SymbolSparkle), phaseCfg.Target)

		return runPhaseRunner(opts, settings, repo)
	}
}
