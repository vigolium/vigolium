// Package codexsdk provides a Go client for the Codex app-server JSON-RPC v2 protocol.
// It spawns `codex app-server --listen stdio://` as a subprocess and communicates via
// newline-delimited JSON over stdin/stdout.
package codexsdk

// Options configures a Codex app-server session.
type Options struct {
	// Executable path. Defaults to "codex" (resolved via $PATH).
	Executable string

	// Working directory for the app-server process.
	Cwd string

	// Model selection (e.g., "o3", "gpt-4.1").
	Model string

	// Config overrides passed as --config key=value flags.
	ConfigOverrides []string

	// Sandbox mode: "read-only", "workspace-write", "danger-full-access".
	Sandbox string

	// Approval policy: "never", "on-request", etc.
	ApprovalPolicy string

	// Base instructions (system prompt).
	BaseInstructions string

	// Developer instructions.
	DeveloperInstructions string

	// Personality: "none", "friendly", "pragmatic".
	Personality string

	// Environment variables for the subprocess.
	Env map[string]string

	// RawArgs overrides the entire argument list when set (for testing or custom commands).
	// When empty, the standard `app-server --listen stdio://` args are used.
	RawArgs []string
}

// buildArgs constructs CLI arguments from Options.
func (o *Options) buildArgs() []string {
	// RawArgs bypass: use exactly these args (for testing or custom commands)
	if len(o.RawArgs) > 0 {
		return o.RawArgs
	}

	var args []string

	// Config overrides come before the subcommand
	for _, kv := range o.ConfigOverrides {
		args = append(args, "--config", kv)
	}

	// Model override as config
	if o.Model != "" {
		args = append(args, "--config", "model="+o.Model)
	}

	args = append(args, "app-server", "--listen", "stdio://")

	return args
}
