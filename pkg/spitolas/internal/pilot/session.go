package pilot

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"

	acp "github.com/coder/acp-go-sdk"
	"github.com/vigolium/vigolium/internal/config"
	"go.uber.org/zap"
)

// pilotResult holds the output of a single ACP prompt turn.
type pilotResult struct {
	Stdout    string
	SessionID string
}

// pilotSession holds a long-lived ACP session for multi-turn pilot crawling.
// Unlike RunAgenticACP (which spawns and kills per call), pilotSession stays
// alive across multiple Prompt calls — the subprocess, connection, and session
// are reused for the entire crawl.
type pilotSession struct {
	conn      *acp.ClientSideConnection
	sessionID acp.SessionId
	client    *pilotACPClient
	cmd       *exec.Cmd

	stdinPipe    io.WriteCloser
	stderrWriter *io.PipeWriter
	stderrWg     sync.WaitGroup

	dead atomic.Bool
}

// spawnPilotSession creates a long-lived ACP session for pilot crawling.
// It spawns the subprocess, initializes the ACP connection, and creates a
// session with MCP servers. The session is ready for multiple Prompt calls.
func spawnPilotSession(ctx context.Context, agentDef config.AgentDef, mcpServers []acp.McpServer, sessionMeta *config.ACPSessionMeta) (*pilotSession, error) {
	if agentDef.Command == "" {
		return nil, fmt.Errorf("agent command is empty")
	}

	cmdPath, err := exec.LookPath(agentDef.Command)
	if err != nil {
		return nil, fmt.Errorf("agent command %q not found in PATH: %w", agentDef.Command, err)
	}

	zap.L().Info("spawning pilot ACP session",
		zap.String("cmd", cmdPath+" "+strings.Join(agentDef.Args, " ")))

	cmd := exec.Command(cmdPath, agentDef.Args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	if len(agentDef.Env) > 0 {
		cmd.Env = cmd.Environ()
		for k, v := range agentDef.Env {
			cmd.Env = append(cmd.Env, k+"="+v)
		}
	}

	stdinPipe, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdin pipe: %w", err)
	}

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	stderrReader, stderrWriter := io.Pipe()
	cmd.Stderr = stderrWriter

	if err := cmd.Start(); err != nil {
		_ = stderrWriter.Close()
		return nil, fmt.Errorf("failed to start agent process: %w", err)
	}

	ps := &pilotSession{
		cmd:          cmd,
		stdinPipe:    stdinPipe,
		stderrWriter: stderrWriter,
		client:       newPilotACPClient(),
	}

	// Drain stderr in background
	ps.stderrWg.Add(1)
	go func() {
		defer ps.stderrWg.Done()
		scanner := bufio.NewScanner(stderrReader)
		for scanner.Scan() {
			zap.L().Debug("agent stderr (pilot)", zap.String("line", scanner.Text()))
		}
	}()

	conn := acp.NewClientSideConnection(ps.client, stdinPipe, stdoutPipe)
	conn.SetLogger(slog.New(newZapSlogHandler()))
	ps.conn = conn

	// Initialize ACP connection
	_, initErr := conn.Initialize(ctx, acp.InitializeRequest{
		ProtocolVersion: acp.ProtocolVersionNumber,
		ClientCapabilities: acp.ClientCapabilities{
			Fs: acp.FileSystemCapability{
				ReadTextFile:  true,
				WriteTextFile: false,
			},
			Terminal: false,
		},
	})
	if initErr != nil {
		ps.Kill()
		return nil, fmt.Errorf("ACP initialize failed: %w", initErr)
	}

	// Determine working directory
	cwd := "."
	if absCwd, absErr := filepath.Abs(cwd); absErr == nil {
		cwd = absCwd
	}

	// Create session with MCP servers
	sessReq := acp.NewSessionRequest{
		Cwd:        cwd,
		McpServers: mcpServers,
	}
	if sessReq.McpServers == nil {
		sessReq.McpServers = []acp.McpServer{}
	}
	if sessionMeta != nil {
		sessReq.Meta = sessionMeta
	}
	sess, sessErr := conn.NewSession(ctx, sessReq)
	if sessErr != nil {
		ps.Kill()
		return nil, fmt.Errorf("ACP new session failed: %w", sessErr)
	}

	ps.sessionID = sess.SessionId
	fmt.Fprintf(os.Stderr, "◆ ACP pilot session: %s\n", string(sess.SessionId))

	// Set model override if configured (UNSTABLE ACP extension — may change).
	if agentDef.Model != "" {
		if _, err := conn.SetSessionModel(ctx, acp.SetSessionModelRequest{
			SessionId: sess.SessionId,
			ModelId:   acp.ModelId(agentDef.Model),
		}); err != nil {
			zap.L().Warn("failed to set session model",
				zap.String("model", agentDef.Model), zap.Error(err))
		} else {
			zap.L().Info("pilot session model set", zap.String("model", agentDef.Model))
		}
	}

	zap.L().Info("pilot ACP session created",
		zap.String("sessionId", string(sess.SessionId)),
		zap.Int("mcpServers", len(mcpServers)))

	return ps, nil
}

// Prompt sends a prompt to the existing ACP session and waits for the agent
// to complete. The output buffer is reset before each call so only the
// current turn's output is returned.
func (ps *pilotSession) Prompt(ctx context.Context, prompt string) (pilotResult, error) {
	ps.client.resetOutput()

	promptResp, promptErr := ps.conn.Prompt(ctx, acp.PromptRequest{
		SessionId: ps.sessionID,
		Prompt:    []acp.ContentBlock{acp.TextBlock(prompt)},
	})
	if promptErr != nil {
		r := pilotResult{Stdout: ps.client.collectedOutput(), SessionID: string(ps.sessionID)}
		if errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(ctx.Err(), context.Canceled) {
			return r, fmt.Errorf("ACP prompt timed out: %w", ctx.Err())
		}
		return r, fmt.Errorf("ACP prompt failed: %w", promptErr)
	}

	zap.L().Debug("pilot ACP prompt completed",
		zap.String("stopReason", string(promptResp.StopReason)),
		zap.Int("outputBytes", len(ps.client.collectedOutput())))

	return pilotResult{
		Stdout:    ps.client.collectedOutput(),
		SessionID: string(ps.sessionID),
	}, nil
}

// Kill terminates the subprocess. Only call once when done with the session.
func (ps *pilotSession) Kill() {
	if !ps.dead.CompareAndSwap(false, true) {
		return
	}
	_ = ps.stdinPipe.Close()
	_ = ps.stderrWriter.Close()
	ps.stderrWg.Wait()
	if ps.cmd.Process != nil {
		_ = syscall.Kill(-ps.cmd.Process.Pid, syscall.SIGKILL)
	}
	_ = ps.cmd.Wait()
	zap.L().Debug("pilot ACP session killed")
}

// Alive checks if the subprocess is still running.
func (ps *pilotSession) Alive() bool {
	if ps.dead.Load() {
		return false
	}
	if ps.cmd == nil || ps.cmd.Process == nil {
		return false
	}
	if err := ps.cmd.Process.Signal(syscall.Signal(0)); err != nil {
		ps.dead.Store(true)
		return false
	}
	return true
}

// --- Error helpers ---

// isACPPromptTimeout returns true if the error is an ACP prompt timeout (retryable).
func isACPPromptTimeout(err error) bool {
	return err != nil && strings.Contains(err.Error(), "ACP prompt timed out")
}

// isACPPromptError returns true if the error is an ACP prompt failure (non-timeout).
// These errors (e.g. "Prompt is too long") are retryable because the browser is still alive.
func isACPPromptError(err error) bool {
	return err != nil && strings.Contains(err.Error(), "ACP prompt failed")
}

// --- Minimal ACP client for pilot sessions ---

// pilotACPClient implements acp.Client for pilot sessions.
// It accumulates agent output text and auto-approves permission requests.
// No terminal or file-write capabilities are needed.
type pilotACPClient struct {
	mu     sync.Mutex
	output strings.Builder
}

var _ acp.Client = (*pilotACPClient)(nil)

func newPilotACPClient() *pilotACPClient {
	return &pilotACPClient{}
}

func (c *pilotACPClient) collectedOutput() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.output.String()
}

func (c *pilotACPClient) resetOutput() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.output.Reset()
}

func (c *pilotACPClient) SessionUpdate(_ context.Context, n acp.SessionNotification) error {
	update := n.Update

	if update.AgentMessageChunk != nil {
		if update.AgentMessageChunk.Content.Text != nil {
			text := update.AgentMessageChunk.Content.Text.Text
			c.mu.Lock()
			c.output.WriteString(text)
			c.mu.Unlock()
		}
	}

	if update.AgentThoughtChunk != nil {
		if update.AgentThoughtChunk.Content.Text != nil {
			zap.L().Debug("pilot thought", zap.String("text", update.AgentThoughtChunk.Content.Text.Text))
		}
	}

	if update.ToolCall != nil {
		zap.L().Debug("pilot tool call",
			zap.String("toolCallId", string(update.ToolCall.ToolCallId)),
			zap.String("title", update.ToolCall.Title),
			zap.String("status", string(update.ToolCall.Status)))
	}

	return nil
}

func (c *pilotACPClient) RequestPermission(_ context.Context, p acp.RequestPermissionRequest) (acp.RequestPermissionResponse, error) {
	// Prefer allow_once, then allow_always, then first option
	for _, opt := range p.Options {
		if opt.Kind == acp.PermissionOptionKindAllowOnce {
			return acp.RequestPermissionResponse{
				Outcome: acp.NewRequestPermissionOutcomeSelected(opt.OptionId),
			}, nil
		}
	}
	for _, opt := range p.Options {
		if opt.Kind == acp.PermissionOptionKindAllowAlways {
			return acp.RequestPermissionResponse{
				Outcome: acp.NewRequestPermissionOutcomeSelected(opt.OptionId),
			}, nil
		}
	}
	if len(p.Options) > 0 {
		return acp.RequestPermissionResponse{
			Outcome: acp.NewRequestPermissionOutcomeSelected(p.Options[0].OptionId),
		}, nil
	}
	return acp.RequestPermissionResponse{
		Outcome: acp.NewRequestPermissionOutcomeCancelled(),
	}, nil
}

func (c *pilotACPClient) ReadTextFile(_ context.Context, p acp.ReadTextFileRequest) (acp.ReadTextFileResponse, error) {
	absPath, err := filepath.Abs(p.Path)
	if err != nil {
		return acp.ReadTextFileResponse{}, fmt.Errorf("invalid path: %w", err)
	}

	data, err := os.ReadFile(absPath)
	if err != nil {
		return acp.ReadTextFileResponse{}, err
	}

	content := string(data)

	if p.Line != nil || p.Limit != nil {
		lines := strings.Split(content, "\n")
		start := 0
		if p.Line != nil && *p.Line > 0 {
			start = *p.Line - 1
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

	return acp.ReadTextFileResponse{Content: content}, nil
}

func (c *pilotACPClient) WriteTextFile(_ context.Context, _ acp.WriteTextFileRequest) (acp.WriteTextFileResponse, error) {
	return acp.WriteTextFileResponse{}, fmt.Errorf("file writes are disabled in pilot mode")
}

func (c *pilotACPClient) CreateTerminal(_ context.Context, _ acp.CreateTerminalRequest) (acp.CreateTerminalResponse, error) {
	return acp.CreateTerminalResponse{TerminalId: "pilot-stub"}, nil
}

func (c *pilotACPClient) KillTerminalCommand(_ context.Context, _ acp.KillTerminalCommandRequest) (acp.KillTerminalCommandResponse, error) {
	return acp.KillTerminalCommandResponse{}, nil
}

func (c *pilotACPClient) ReleaseTerminal(_ context.Context, _ acp.ReleaseTerminalRequest) (acp.ReleaseTerminalResponse, error) {
	return acp.ReleaseTerminalResponse{}, nil
}

func (c *pilotACPClient) TerminalOutput(_ context.Context, _ acp.TerminalOutputRequest) (acp.TerminalOutputResponse, error) {
	return acp.TerminalOutputResponse{Output: "", Truncated: false}, nil
}

func (c *pilotACPClient) WaitForTerminalExit(_ context.Context, _ acp.WaitForTerminalExitRequest) (acp.WaitForTerminalExitResponse, error) {
	exitCode := 0
	return acp.WaitForTerminalExitResponse{ExitCode: &exitCode}, nil
}

// --- Slog handler for ACP SDK ---

type zapSlogHandler struct{}

func newZapSlogHandler() *zapSlogHandler { return &zapSlogHandler{} }

func (h *zapSlogHandler) Enabled(_ context.Context, _ slog.Level) bool { return true }

func (h *zapSlogHandler) Handle(_ context.Context, r slog.Record) error {
	zap.L().Debug("acp-sdk: "+r.Message, zap.String("level", r.Level.String()))
	return nil
}

func (h *zapSlogHandler) WithAttrs(_ []slog.Attr) slog.Handler { return h }
func (h *zapSlogHandler) WithGroup(_ string) slog.Handler      { return h }
