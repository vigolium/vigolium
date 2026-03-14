package agent

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	acp "github.com/coder/acp-go-sdk"
	"go.uber.org/zap"
)

// acpClientOption configures an acpClient.
type acpClientOption func(*acpClient)

// withAllowedPaths restricts ReadTextFile to files under the given directories.
func withAllowedPaths(paths ...string) acpClientOption {
	return func(c *acpClient) {
		c.allowedPaths = append(c.allowedPaths, paths...)
	}
}

// withStreamWriter sets a writer for real-time output streaming.
func withStreamWriter(w io.Writer) acpClientOption {
	return func(c *acpClient) {
		c.streamWriter = w
	}
}

// withSessionWeight sets the session importance weight (higher = less likely to be evicted).
func withSessionWeight(w int) acpClientOption {
	return func(c *acpClient) {
		c.sessionWeight = w
	}
}

// withSessionKey overrides the pool map key for this prompt.
// When set, the pool uses this key (instead of agent name) to look up and store sessions,
// preventing context accumulation across different phases that use the same agent.
func withSessionKey(key string) acpClientOption {
	return func(c *acpClient) {
		c.sessionKey = key
	}
}

// acpClient implements the acp.Client interface for Vigolium's scanner mode.
// It accumulates agent output text and auto-approves permission requests.
// When termMgr is set (autopilot mode), terminal methods execute real commands.
type acpClient struct {
	mu           sync.Mutex
	output       strings.Builder
	allowedPaths []string
	streamWriter  io.Writer
	termMgr       *terminalManager // nil in scanner mode, set in autopilot mode
	sessionWeight int
	sessionKey    string // overrides agent name as pool map key when set
}

var _ acp.Client = (*acpClient)(nil)

func newACPClient(opts ...acpClientOption) *acpClient {
	c := &acpClient{}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// collectedOutput returns the accumulated agent text output.
func (c *acpClient) collectedOutput() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.output.String()
}

// resetOutput clears the accumulated output buffer for session reuse.
func (c *acpClient) resetOutput() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.output.Reset()
}

// setStreamWriter updates the stream writer between prompts.
func (c *acpClient) setStreamWriter(w io.Writer) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.streamWriter = w
}

// SessionUpdate receives streaming updates from the agent.
// Agent message chunks are accumulated as output text.
func (c *acpClient) SessionUpdate(_ context.Context, n acp.SessionNotification) error {
	update := n.Update

	if update.AgentMessageChunk != nil {
		if update.AgentMessageChunk.Content.Text != nil {
			text := update.AgentMessageChunk.Content.Text.Text
			c.mu.Lock()
			c.output.WriteString(text)
			c.mu.Unlock()

			if c.streamWriter != nil {
				// Best-effort write; don't fail the session on stream errors.
				_, _ = io.WriteString(c.streamWriter, text)
			}
		}
	}

	if update.AgentThoughtChunk != nil {
		if update.AgentThoughtChunk.Content.Text != nil {
			zap.L().Debug("agent thought", zap.String("text", update.AgentThoughtChunk.Content.Text.Text))
		}
	}

	if update.ToolCall != nil {
		fields := []zap.Field{
			zap.String("toolCallId", string(update.ToolCall.ToolCallId)),
			zap.String("title", update.ToolCall.Title),
			zap.String("status", string(update.ToolCall.Status)),
		}
		if update.ToolCall.Kind != "" {
			fields = append(fields, zap.String("kind", string(update.ToolCall.Kind)))
		}
		if len(update.ToolCall.Locations) > 0 {
			paths := make([]string, len(update.ToolCall.Locations))
			for i, loc := range update.ToolCall.Locations {
				paths[i] = loc.Path
			}
			fields = append(fields, zap.Strings("paths", paths))
		}
		zap.L().Debug("agent tool call", fields...)
	}

	if update.ToolCallUpdate != nil {
		fields := []zap.Field{
			zap.String("toolCallId", string(update.ToolCallUpdate.ToolCallId)),
		}
		if update.ToolCallUpdate.Status != nil {
			fields = append(fields, zap.String("status", string(*update.ToolCallUpdate.Status)))
		}
		if update.ToolCallUpdate.Title != nil {
			fields = append(fields, zap.String("title", *update.ToolCallUpdate.Title))
		}
		zap.L().Debug("agent tool call update", fields...)
	}

	if update.Plan != nil {
		entries := make([]string, len(update.Plan.Entries))
		for i, e := range update.Plan.Entries {
			entries[i] = fmt.Sprintf("[%s] %s", string(e.Status), e.Content)
		}
		zap.L().Debug("agent plan update",
			zap.Strings("entries", entries))
	}

	return nil
}

// RequestPermission auto-approves agent permission requests by selecting the
// first allow_once or allow_always option. If no allow option is found, the
// first option is selected.
func (c *acpClient) RequestPermission(_ context.Context, p acp.RequestPermissionRequest) (acp.RequestPermissionResponse, error) {
	toolTitle := ""
	if p.ToolCall.Title != nil {
		toolTitle = *p.ToolCall.Title
	}

	optionNames := make([]string, len(p.Options))
	for i, opt := range p.Options {
		optionNames[i] = fmt.Sprintf("%s(%s)", opt.Name, opt.Kind)
	}
	zap.L().Debug("agent requested permission",
		zap.String("toolCallId", string(p.ToolCall.ToolCallId)),
		zap.String("toolTitle", toolTitle),
		zap.Strings("options", optionNames))

	// Prefer allow_once, then allow_always, then first option
	for _, opt := range p.Options {
		if opt.Kind == acp.PermissionOptionKindAllowOnce {
			zap.L().Debug("auto-approved permission",
				zap.String("selected", opt.Name),
				zap.String("kind", string(opt.Kind)))
			return acp.RequestPermissionResponse{
				Outcome: acp.NewRequestPermissionOutcomeSelected(opt.OptionId),
			}, nil
		}
	}
	for _, opt := range p.Options {
		if opt.Kind == acp.PermissionOptionKindAllowAlways {
			zap.L().Debug("auto-approved permission",
				zap.String("selected", opt.Name),
				zap.String("kind", string(opt.Kind)))
			return acp.RequestPermissionResponse{
				Outcome: acp.NewRequestPermissionOutcomeSelected(opt.OptionId),
			}, nil
		}
	}
	if len(p.Options) > 0 {
		zap.L().Debug("auto-approved permission (fallback to first option)",
			zap.String("selected", p.Options[0].Name),
			zap.String("kind", string(p.Options[0].Kind)))
		return acp.RequestPermissionResponse{
			Outcome: acp.NewRequestPermissionOutcomeSelected(p.Options[0].OptionId),
		}, nil
	}
	zap.L().Debug("permission request cancelled (no options available)")
	return acp.RequestPermissionResponse{
		Outcome: acp.NewRequestPermissionOutcomeCancelled(),
	}, nil
}

// ReadTextFile reads a file from disk, scoped to allowed paths.
// Supports optional Line (1-indexed start) and Limit (number of lines) parameters.
func (c *acpClient) ReadTextFile(_ context.Context, p acp.ReadTextFileRequest) (acp.ReadTextFileResponse, error) {
	absPath, err := filepath.Abs(p.Path)
	if err != nil {
		return acp.ReadTextFileResponse{}, fmt.Errorf("invalid path: %w", err)
	}

	if !c.isPathAllowed(absPath) {
		zap.L().Debug("agent ReadTextFile denied (outside allowed paths)",
			zap.String("path", p.Path),
			zap.Strings("allowedPaths", c.allowedPaths))
		return acp.ReadTextFileResponse{}, fmt.Errorf("path %q is outside allowed directories", p.Path)
	}

	data, err := os.ReadFile(absPath)
	if err != nil {
		zap.L().Debug("agent ReadTextFile failed",
			zap.String("path", absPath),
			zap.Error(err))
		return acp.ReadTextFileResponse{}, err
	}

	content := string(data)

	// Apply Line/Limit slicing if requested
	if p.Line != nil || p.Limit != nil {
		lines := strings.Split(content, "\n")
		start := 0
		if p.Line != nil && *p.Line > 0 {
			start = *p.Line - 1 // 1-indexed to 0-indexed
			if start > len(lines) {
				start = len(lines)
			}
		}
		end := len(lines)
		if p.Limit != nil && *p.Limit > 0 {
			if start+*p.Limit < end {
				end = start + *p.Limit
			}
		}
		content = strings.Join(lines[start:end], "\n")
	}

	zap.L().Debug("agent ReadTextFile",
		zap.String("path", absPath),
		zap.Int("bytes", len(content)))

	return acp.ReadTextFileResponse{Content: content}, nil
}

// WriteTextFile is disabled in scanner mode.
func (c *acpClient) WriteTextFile(_ context.Context, p acp.WriteTextFileRequest) (acp.WriteTextFileResponse, error) {
	zap.L().Debug("agent WriteTextFile denied (scanner mode)",
		zap.String("path", p.Path))
	return acp.WriteTextFileResponse{}, fmt.Errorf("file writes are disabled in scanner mode")
}

// CreateTerminal creates a terminal session. In scanner mode, returns a stub.
// In autopilot mode, validates and executes the command.
func (c *acpClient) CreateTerminal(ctx context.Context, p acp.CreateTerminalRequest) (acp.CreateTerminalResponse, error) {
	if c.termMgr == nil {
		// Scanner mode — stub (returning error causes the agent to hang)
		zap.L().Debug("agent CreateTerminal (no-op)",
			zap.String("command", p.Command))
		return acp.CreateTerminalResponse{TerminalId: "vigolium-stub-term"}, nil
	}

	// Autopilot mode — validate and execute
	if err := c.termMgr.validateCommand(p.Command); err != nil {
		zap.L().Warn("agent CreateTerminal denied",
			zap.String("command", p.Command),
			zap.Error(err))
		return acp.CreateTerminalResponse{}, err
	}

	sess, err := c.termMgr.createSession(ctx, p.Command)
	if err != nil {
		return acp.CreateTerminalResponse{}, err
	}

	return acp.CreateTerminalResponse{TerminalId: sess.id}, nil
}

// KillTerminalCommand terminates a running terminal command.
func (c *acpClient) KillTerminalCommand(_ context.Context, p acp.KillTerminalCommandRequest) (acp.KillTerminalCommandResponse, error) {
	if c.termMgr == nil {
		zap.L().Debug("agent KillTerminalCommand (no-op)")
		return acp.KillTerminalCommandResponse{}, nil
	}

	c.termMgr.killSession(string(p.TerminalId))
	return acp.KillTerminalCommandResponse{}, nil
}

// ReleaseTerminal releases a terminal session.
func (c *acpClient) ReleaseTerminal(_ context.Context, p acp.ReleaseTerminalRequest) (acp.ReleaseTerminalResponse, error) {
	if c.termMgr == nil {
		zap.L().Debug("agent ReleaseTerminal (no-op)")
		return acp.ReleaseTerminalResponse{}, nil
	}

	c.termMgr.releaseSession(string(p.TerminalId))
	return acp.ReleaseTerminalResponse{}, nil
}

// TerminalOutput returns the output of a terminal session.
func (c *acpClient) TerminalOutput(_ context.Context, p acp.TerminalOutputRequest) (acp.TerminalOutputResponse, error) {
	if c.termMgr == nil {
		zap.L().Debug("agent TerminalOutput (no-op)")
		return acp.TerminalOutputResponse{Output: "", Truncated: false}, nil
	}

	output, truncated := c.termMgr.getOutput(string(p.TerminalId))
	return acp.TerminalOutputResponse{Output: output, Truncated: truncated}, nil
}

// WaitForTerminalExit waits for a terminal session to complete.
func (c *acpClient) WaitForTerminalExit(ctx context.Context, p acp.WaitForTerminalExitRequest) (acp.WaitForTerminalExitResponse, error) {
	if c.termMgr == nil {
		zap.L().Debug("agent WaitForTerminalExit (no-op)")
		exitCode := 0
		return acp.WaitForTerminalExitResponse{ExitCode: &exitCode}, nil
	}

	exitCode := c.termMgr.waitForExit(ctx, string(p.TerminalId))
	return acp.WaitForTerminalExitResponse{ExitCode: &exitCode}, nil
}

// isPathAllowed checks if a path is under one of the allowed directories.
// If no allowed paths are configured, all paths are allowed.
func (c *acpClient) isPathAllowed(absPath string) bool {
	if len(c.allowedPaths) == 0 {
		return true
	}
	for _, allowed := range c.allowedPaths {
		allowedAbs, err := filepath.Abs(allowed)
		if err != nil {
			continue
		}
		// Ensure the allowed path ends with separator for proper prefix matching
		prefix := allowedAbs + string(filepath.Separator)
		if absPath == allowedAbs || strings.HasPrefix(absPath, prefix) {
			return true
		}
	}
	return false
}
