package agent

import (
	"bufio"
	"bytes"
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
	"syscall"

	acp "github.com/coder/acp-go-sdk"
	"github.com/vigolium/vigolium/internal/config"
	"go.uber.org/zap"
)

// acpRunConfig holds optional configuration that varies between scanner and autopilot modes.
type acpRunConfig struct {
	Terminal    bool   // enable terminal capability in ACP
	Cwd         string // explicit working directory (bypasses probe extraction from opts)
	MaxCalls    int    // max terminal commands (only used when Terminal is true)
	SessionMeta *config.ACPSessionMeta // optional session metadata passed via NewSessionRequest._meta
}

// acpResult holds the output of an ACP agent run.
type acpResult struct {
	Stdout    string
	Stderr    string
	SessionID string // ACP session ID for resume
}

// RunAgenticACP executes an AI agent using the ACP protocol.
// It returns the collected agent output, stderr, and any execution error.
func RunAgenticACP(ctx context.Context, agentDef config.AgentDef, prompt string, opts ...acpClientOption) (result acpResult, err error) {
	return runACP(ctx, agentDef, prompt, acpRunConfig{
		SessionMeta: agentDef.SessionMeta,
	}, opts...)
}

// RunAgenticAutopilot executes an AI agent using the ACP protocol with terminal
// capabilities enabled. The agent can run vigolium CLI commands via CreateTerminal.
func RunAgenticAutopilot(ctx context.Context, agentDef config.AgentDef, prompt string, cwd string, maxCalls int, opts ...acpClientOption) (result acpResult, err error) {
	opts = append(opts, withTerminal(cwd, maxCalls))
	return runACP(ctx, agentDef, prompt, acpRunConfig{
		Terminal:    true,
		Cwd:         cwd,
		MaxCalls:    maxCalls,
		SessionMeta: agentDef.SessionMeta,
	}, opts...)
}

// runACP is the shared implementation for both RunAgenticACP and RunAgenticAutopilot.
func runACP(ctx context.Context, agentDef config.AgentDef, prompt string, cfg acpRunConfig, opts ...acpClientOption) (result acpResult, err error) {
	if agentDef.Command == "" {
		return acpResult{}, fmt.Errorf("agent command is empty")
	}

	cmdPath, err := exec.LookPath(agentDef.Command)
	if err != nil {
		return acpResult{}, fmt.Errorf("agent command %q not found in PATH: %w", agentDef.Command, err)
	}

	cmdLine := cmdPath + " " + strings.Join(agentDef.Args, " ")
	zap.L().Debug("starting agent subprocess (ACP mode)",
		zap.String("cmd", cmdLine),
		zap.Int("promptLength", len(prompt)),
		zap.Bool("terminal", cfg.Terminal))

	cmd := exec.CommandContext(ctx, cmdPath, agentDef.Args...)

	// Create a new process group so we can kill the entire tree (e.g. npx + child node process).
	// Without this, killing only the top-level process leaves children alive holding pipe fds,
	// which causes cmd.Wait() to hang on the internal I/O goroutine.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	if len(agentDef.Env) > 0 {
		cmd.Env = cmd.Environ()
		for k, v := range agentDef.Env {
			cmd.Env = append(cmd.Env, k+"="+v)
		}
	}

	stdinPipe, err := cmd.StdinPipe()
	if err != nil {
		return acpResult{}, fmt.Errorf("failed to create stdin pipe: %w", err)
	}

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return acpResult{}, fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	stderrReader, stderrWriter := io.Pipe()
	cmd.Stderr = stderrWriter

	if err := cmd.Start(); err != nil {
		_ = stderrWriter.Close()
		return acpResult{}, fmt.Errorf("failed to start agent process: %w", err)
	}

	// Drain stderr in background, logging each line in real-time
	var stderrBuf bytes.Buffer
	var stderrWg sync.WaitGroup
	stderrWg.Add(1)
	go func() {
		defer stderrWg.Done()
		scanner := bufio.NewScanner(stderrReader)
		for scanner.Scan() {
			line := scanner.Text()
			stderrBuf.WriteString(line)
			stderrBuf.WriteByte('\n')
			zap.L().Debug("agent stderr", zap.String("line", line))
		}
	}()

	client := newACPClient(opts...)

	defer func() {
		// Kill any orphaned terminal sessions before killing the agent process
		if client.termMgr != nil {
			client.termMgr.killAll()
		}
		// Close the pipe writer so the drain goroutine finishes
		_ = stderrWriter.Close()
		stderrWg.Wait()
		// Kill the entire process group to ensure child processes (e.g. spawned by npx)
		// are also terminated, preventing pipe fd leaks that cause cmd.Wait() to hang.
		if cmd.Process != nil {
			killProcessGroup(cmd.Process.Pid, "acp-runner")
		}
		_ = cmd.Wait()
	}()

	conn := acp.NewClientSideConnection(client, stdinPipe, stdoutPipe)

	// Suppress the SDK's default INFO logs (e.g. "peer connection closed") so they
	// only appear at DEBUG level, routed through our zap logger.
	conn.SetLogger(slog.New(newZapSlogHandler()))

	zap.L().Debug("ACP connection established, sending Initialize request",
		zap.Int("protocolVersion", acp.ProtocolVersionNumber))

	// Initialize the ACP connection
	initResp, initErr := conn.Initialize(ctx, acp.InitializeRequest{
		ProtocolVersion: acp.ProtocolVersionNumber,
		ClientCapabilities: acp.ClientCapabilities{
			Fs: acp.FileSystemCapability{
				ReadTextFile:  true,
				WriteTextFile: false,
			},
			Terminal: cfg.Terminal,
		},
	})
	if initErr != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return acpResult{Stderr: stderrBuf.String()}, fmt.Errorf("ACP initialize timed out: %w", ctx.Err())
		}
		return acpResult{Stderr: stderrBuf.String()}, fmt.Errorf("ACP initialize failed: %w", initErr)
	}

	zap.L().Debug("ACP initialized successfully")

	// Determine working directory for the session
	cwd := cfg.Cwd
	if cwd == "" {
		cwd = "."
		for _, opt := range opts {
			// Extract allowedPaths to use as cwd — apply options to a temp client to inspect
			probe := &acpClient{}
			opt(probe)
			if len(probe.allowedPaths) > 0 {
				cwd = probe.allowedPaths[0]
			}
		}
	}

	// Resolve to absolute path — ACP bridges require absolute cwd
	if absCwd, absErr := filepath.Abs(cwd); absErr == nil {
		cwd = absCwd
	}

	zap.L().Debug("creating ACP session", zap.String("cwd", cwd))

	// Create a new session
	sessReq := acp.NewSessionRequest{
		Cwd:        cwd,
		McpServers: []acp.McpServer{},
	}
	if cfg.SessionMeta != nil {
		sessReq.Meta = cfg.SessionMeta
	}
	sess, sessErr := conn.NewSession(ctx, sessReq)
	if sessErr != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return acpResult{Stderr: stderrBuf.String()}, fmt.Errorf("ACP session creation timed out: %w", ctx.Err())
		}
		return acpResult{Stderr: stderrBuf.String()}, fmt.Errorf("ACP new session failed: %w", sessErr)
	}

	sessionID := string(sess.SessionId)

	fmt.Fprintf(os.Stderr, "◆ ACP session: %s\n", sessionID)

	zap.L().Debug("sending ACP prompt, waiting for agent completion...",
		zap.Int("promptLength", len(prompt)))

	// Send the prompt — this blocks until the agent completes
	promptResp, promptErr := conn.Prompt(ctx, acp.PromptRequest{
		SessionId: sess.SessionId,
		Prompt:    []acp.ContentBlock{acp.TextBlock(prompt)},
	})
	if promptErr != nil {
		r := acpResult{Stdout: client.collectedOutput(), Stderr: stderrBuf.String(), SessionID: sessionID}
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return r, fmt.Errorf("ACP prompt timed out: %w", ctx.Err())
		}
		return r, fmt.Errorf("ACP prompt failed: %w", promptErr)
	}

	output := client.collectedOutput()

	zap.L().Debug("ACP prompt completed",
		zap.String("stopReason", string(promptResp.StopReason)),
		zap.Int("collectedOutputBytes", len(output)))

	// Close stdin to signal EOF to the agent process
	_ = stdinPipe.Close()

	if len(output) == 0 && promptResp.StopReason == "end_turn" {
		var authHint string
		if len(initResp.AuthMethods) > 0 {
			hints := make([]string, 0, len(initResp.AuthMethods))
			for _, am := range initResp.AuthMethods {
				desc := am.Name
			if am.Description != nil && *am.Description != "" {
				desc = *am.Description
			}
			hints = append(hints, desc)
			}
			authHint = fmt.Sprintf("; the agent advertises authentication methods — ensure you are authenticated: %s", strings.Join(hints, "; "))
		}

		return acpResult{
			Stdout:    output,
			Stderr:    stderrBuf.String(),
			SessionID: sessionID,
		}, fmt.Errorf("agent returned empty output (0 tokens) — the LLM backend did not process the prompt%s", authHint)
	}

	return acpResult{
		Stdout:    output,
		Stderr:    stderrBuf.String(),
		SessionID: sessionID,
	}, nil
}

// zapSlogHandler routes slog records through zap, downgrading everything to DEBUG level.
type zapSlogHandler struct{}

func newZapSlogHandler() *zapSlogHandler { return &zapSlogHandler{} }

func (h *zapSlogHandler) Enabled(_ context.Context, _ slog.Level) bool { return true }

func (h *zapSlogHandler) Handle(_ context.Context, r slog.Record) error {
	zap.L().Debug("acp-sdk: "+r.Message, zap.String("level", r.Level.String()))
	return nil
}

func (h *zapSlogHandler) WithAttrs(_ []slog.Attr) slog.Handler { return h }
func (h *zapSlogHandler) WithGroup(_ string) slog.Handler      { return h }
