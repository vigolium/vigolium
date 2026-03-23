// Package opencodesdk provides a Go client wrapper around the OpenCode REST API.
// It spawns an `opencode serve` daemon as a subprocess and communicates via
// the official OpenCode SDK over HTTP/SSE.
package opencodesdk

const defaultPort = 54321

// Options configures an OpenCode daemon session.
type Options struct {
	// Executable path. Defaults to "opencode" (resolved via $PATH).
	Executable string

	// Working directory for the daemon process.
	Cwd string

	// Model selection (e.g., "anthropic/claude-sonnet-4-5").
	Model string

	// Port for the daemon HTTP server. Default: 54321.
	Port int

	// Environment variables for the subprocess.
	Env map[string]string

	// System prompt to prepend to sessions.
	SystemPrompt string
}

// EffectivePort returns the configured port or the default (54321).
func (o *Options) EffectivePort() int {
	if o.Port <= 0 {
		return defaultPort
	}
	return o.Port
}
