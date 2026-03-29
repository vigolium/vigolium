package cli

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/agent"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/vigolium/vigolium/pkg/types"
)

// pipeline command flags
var (
	pipelineTarget          string
	pipelineInput           string
	pipelineAgent           string
	pipelineSource          string
	pipelineFiles           []string
	pipelineFocus           string
	pipelineTimeout         time.Duration
	pipelineACPCmd          string
	pipelineDryRun          bool
	pipelineShowPrompt      bool
	pipelineMaxRescanRounds int
	pipelineSkipPhases      []string
	pipelineStartFrom       string
	pipelineProfile         string
	pipelineInstruction     string
	pipelineInstructionFile string
)

var agentPipelineCmd = &cobra.Command{
	Use:   "pipeline",
	Short: "Alias for 'swarm --discover' — multi-phase agentic scan pipeline",
	Long: `Run an agentic scan pipeline (alias for 'vigolium agent swarm --discover').

This command delegates to the swarm engine with discovery enabled, providing
the same multi-phase pipeline experience: source analysis, discovery, planning,
scanning, triage, and rescan.

Pipeline phase names are mapped to swarm phases:
  source-analysis → source-analysis
  discover        → discover
  plan            → plan
  scan            → native-scan
  triage          → triage
  rescan          → rescan
  report          → (no-op, swarm reports inline)

Supported input types for --input (auto-detected):
  - URL:         https://example.com/api/login
  - Curl:        curl -X POST https://example.com/api -d '{"user":"admin"}'
  - Raw HTTP:    POST /api HTTP/1.1\r\nHost: example.com\r\n...
  - Burp XML:    <?xml...><items><item>...</item></items>
  - Base64:      Base64-encoded raw HTTP request (Burp base64 export)

When input is piped via stdin, it is automatically read (no --input needed).
The target URL is extracted from the input when --target is not provided.`,
	RunE: runAgentPipeline,
}

func init() {
	agentCmd.AddCommand(agentPipelineCmd)
	f := agentPipelineCmd.Flags()

	f.StringVarP(&pipelineTarget, "target", "t", "", "Target URL (derived from --input if not set)")
	f.StringVar(&pipelineInput, "input", "", "Raw input (curl command, raw HTTP, Burp XML, URL). Reads from stdin if piped")
	f.StringVar(&pipelineAgent, "agent", "", "Agent backend to use (default from config)")
	f.StringVar(&pipelineACPCmd, "agent-acp-cmd", "", "Custom ACP agent command (e.g. 'traecli acp'), overrides --agent")
	f.StringVar(&pipelineSource, "source", "", "Path to application source code for source-aware scanning")
	f.StringSliceVar(&pipelineFiles, "files", nil, "Specific source files to include (relative to --source)")
	f.StringVar(&pipelineFocus, "focus", "", "Focus area hint for the planning agent (e.g. 'API injection', 'auth bypass')")
	f.DurationVar(&pipelineTimeout, "timeout", 1*time.Hour, "Maximum total pipeline duration")
	f.BoolVar(&pipelineDryRun, "dry-run", false, "Render agent prompts without executing (shows plan and triage prompts)")
	f.BoolVar(&pipelineShowPrompt, "show-prompt", false, "Print rendered prompts to stderr before executing")
	f.IntVar(&pipelineMaxRescanRounds, "max-rescan-rounds", 2, "Maximum number of triage->rescan iterations")
	f.StringSliceVar(&pipelineSkipPhases, "skip-phase", nil, "Skip specific phases (source-analysis, discover, plan, scan, triage, rescan, report)")
	f.StringVar(&pipelineStartFrom, "start-from", "", "Resume pipeline from a specific phase")
	f.StringVar(&pipelineProfile, "profile", "", "Scanning profile to use for scan phases")
	f.StringVar(&pipelineInstruction, "instruction", "", "Custom instruction to guide the agent (appended to prompts)")
	f.StringVar(&pipelineInstructionFile, "instruction-file", "", "Path to a file containing custom instructions")
}

// pipelinePhaseToSwarm maps pipeline phase names to swarm phase names.
var pipelinePhaseToSwarm = map[string]string{
	"source-analysis": agent.SwarmPhaseSourceAnalysis,
	"code-audit":      agent.SwarmPhaseCodeAudit,
	"discover":        agent.SwarmPhaseDiscover,
	"plan":            agent.SwarmPhasePlan,
	"scan":            agent.SwarmPhaseScan,
	"triage":          agent.SwarmPhaseTriage,
	"rescan":          agent.SwarmPhaseRescan,
	"report":          "", // no-op in swarm
}

// mapPipelinePhases converts pipeline --skip-phase values to swarm --skip values.
func mapPipelinePhases(pipelinePhases []string) []string {
	var swarmPhases []string
	for _, p := range pipelinePhases {
		p = strings.TrimSpace(p)
		if mapped, ok := pipelinePhaseToSwarm[p]; ok && mapped != "" {
			swarmPhases = append(swarmPhases, mapped)
		}
	}
	return swarmPhases
}

// mapPipelineStartFrom converts a pipeline --start-from value to a swarm phase name.
func mapPipelineStartFrom(phase string) string {
	if mapped, ok := pipelinePhaseToSwarm[phase]; ok && mapped != "" {
		return mapped
	}
	return phase
}

// runAgentPipeline delegates to runAgentSwarm with --discover enabled.
// Pipeline flags are mapped to their swarm equivalents.
func runAgentPipeline(cmd *cobra.Command, args []string) error {
	// Resolve input and target (pipeline derives target from input)
	resolved, err := resolveInputAndTarget(pipelineTarget, pipelineInput)
	if err != nil {
		return err
	}

	if resolved.Target == "" && pipelineSource == "" {
		return fmt.Errorf("target is required: use --target, --input, --source, or pipe via stdin")
	}
	if resolved.Target == "" {
		fmt.Fprintf(os.Stderr, "%s No --target specified. Running source-only analysis; dynamic testing will be skipped.\n",
			terminal.WarningSymbol())
	}

	// Save current swarm flags to restore after delegation
	savedTarget := swarmTarget
	savedInput := swarmInput
	savedAgentName := swarmAgentName
	savedAgentACPCmd := swarmAgentACPCmd
	savedSource := swarmSource
	savedFiles := swarmFiles
	savedFocus := swarmFocus
	savedVulnType := swarmVulnType
	savedTimeout := swarmTimeout
	savedDryRun := swarmDryRun
	savedShowPrompt := swarmShowPrompt
	savedMaxIterations := swarmMaxIterations
	savedSkipPhases := swarmSkipPhases
	savedStartFrom := swarmStartFrom
	savedProfile := swarmProfile
	savedInstruction := swarmInstruction
	savedInstructionFile := swarmInstructionFile
	savedDiscover := swarmDiscover

	// Map pipeline flags → swarm flags
	swarmTarget = resolved.Target
	// Only set swarmInput if the raw input differs from the resolved target (avoids duplicate inputs)
	if resolved.InputData != "" && resolved.InputData != resolved.Target {
		swarmInput = resolved.InputData
	} else {
		swarmInput = ""
	}
	swarmAgentName = pipelineAgent
	swarmAgentACPCmd = pipelineACPCmd
	swarmSource = pipelineSource
	swarmFiles = pipelineFiles
	swarmFocus = pipelineFocus
	swarmVulnType = "" // pipeline uses --focus, not --vuln-type
	swarmTimeout = pipelineTimeout
	swarmDryRun = pipelineDryRun
	swarmShowPrompt = pipelineShowPrompt
	swarmMaxIterations = pipelineMaxRescanRounds
	swarmSkipPhases = mapPipelinePhases(pipelineSkipPhases)
	swarmStartFrom = mapPipelineStartFrom(pipelineStartFrom)
	swarmProfile = pipelineProfile
	swarmInstruction = pipelineInstruction
	swarmInstructionFile = pipelineInstructionFile
	swarmDiscover = true // key alias behavior

	// Restore swarm flags after delegation
	defer func() {
		swarmTarget = savedTarget
		swarmInput = savedInput
		swarmAgentName = savedAgentName
		swarmAgentACPCmd = savedAgentACPCmd
		swarmSource = savedSource
		swarmFiles = savedFiles
		swarmFocus = savedFocus
		swarmVulnType = savedVulnType
		swarmTimeout = savedTimeout
		swarmDryRun = savedDryRun
		swarmShowPrompt = savedShowPrompt
		swarmMaxIterations = savedMaxIterations
		swarmSkipPhases = savedSkipPhases
		swarmStartFrom = savedStartFrom
		swarmProfile = savedProfile
		swarmInstruction = savedInstruction
		swarmInstructionFile = savedInstructionFile
		swarmDiscover = savedDiscover
	}()

	fmt.Fprintf(os.Stderr, "%s Pipeline mode (delegating to swarm --discover)\n",
		terminal.InfoSymbol())

	return runAgentSwarm(cmd, args)
}

// sessionConfigYAML is the YAML-serializable session config format
// matching pkg/session.SessionConfig.
type sessionConfigYAML struct {
	Sessions []sessionEntryYAML `yaml:"sessions"`
}

type sessionEntryYAML struct {
	Name    string            `yaml:"name"`
	Role    string            `yaml:"role"`
	Headers map[string]string `yaml:"headers,omitempty"`
	Login   *loginFlowYAML    `yaml:"login,omitempty"`
}

type loginFlowYAML struct {
	URL         string            `yaml:"url"`
	Method      string            `yaml:"method"`
	ContentType string            `yaml:"content_type,omitempty"`
	Body        string            `yaml:"body,omitempty"`
	Extract     []extractRuleYAML `yaml:"extract,omitempty"`
	Type        string            `yaml:"type,omitempty"`
	TokenPath   string            `yaml:"token_path,omitempty"`
	Expect      *expectYAML       `yaml:"expect,omitempty"`
}

type expectYAML struct {
	Status       []int  `yaml:"status,omitempty"`
	BodyContains string `yaml:"body_contains,omitempty"`
}

type extractRuleYAML struct {
	Source  string `yaml:"source"`
	Name    string `yaml:"name,omitempty"`
	Path    string `yaml:"path,omitempty"`
	ApplyAs string `yaml:"apply_as,omitempty"`
	Pattern string `yaml:"pattern,omitempty"`
	Group   int    `yaml:"group,omitempty"`
}

// convertSessionConfig converts agent session config to the YAML format expected by pkg/session.
func convertSessionConfig(cfg *agent.AgentSessionConfig) sessionConfigYAML {
	result := sessionConfigYAML{}
	for _, s := range cfg.Sessions {
		entry := sessionEntryYAML{
			Name:    s.Name,
			Role:    s.Role,
			Headers: s.Headers,
		}
		if s.Login != nil {
			login := &loginFlowYAML{
				URL:         s.Login.URL,
				Method:      s.Login.Method,
				ContentType: s.Login.ContentType,
				Body:        s.Login.Body,
				Type:        s.Login.Type,
				TokenPath:   s.Login.TokenPath,
			}
			if s.Login.Expect != nil {
				login.Expect = &expectYAML{
					Status:       s.Login.Expect.Status,
					BodyContains: s.Login.Expect.BodyContains,
				}
			}
			for _, e := range s.Login.Extract {
				login.Extract = append(login.Extract, extractRuleYAML{
					Source:  e.Source,
					Name:    e.Name,
					Path:    e.Path,
					ApplyAs: e.ApplyAs,
					Pattern: e.Pattern,
					Group:   e.Group,
				})
			}
			entry.Login = login
		}
		result.Sessions = append(result.Sessions, entry)
	}
	return result
}

// runPipelinePhaseRunner creates a runner with the given options, executes it, and cleans up.
func runPipelinePhaseRunner(opts *types.Options, settings *config.Settings, repo *database.Repository) error {
	scanRunner, err := runner.New(opts)
	if err != nil {
		return err
	}
	defer scanRunner.Close()

	scanRunner.SetSettings(settings)
	scanRunner.SetRepository(repo)
	return scanRunner.RunNativeScan()
}

// summarizeModules returns a human-readable summary of selected modules.
func summarizeModules(mods []string) string {
	if len(mods) == 1 && mods[0] == "all" {
		return "all modules"
	}
	if len(mods) <= 5 {
		return strings.Join(mods, ", ")
	}
	return fmt.Sprintf("%d modules", len(mods))
}
