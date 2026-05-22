package tool

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/vigolium/vigolium/pkg/procutil"
)

// maxBashCapture bounds how much combined stdout+stderr the bash tool retains in
// memory. Output beyond this is drained from the pipe (so the command never
// blocks on a full pipe) but discarded from the captured result.
const maxBashCapture = 1 << 20 // 1 MiB

// Catastrophic patterns match on a single shell *segment* (a piece
// between separators like `;`, `&&`, `||`, `|`, or newline). Segmenting
// first avoids false positives on things like `echo "rm -rf /"` or
// `git log --grep="rm -rf /"`, where the dangerous text is an argument
// to a benign command, not an actual invocation.
//
// Each pattern must describe a command a reasonable human would never
// type on purpose. When in doubt, let it through — olium is yolo by
// default and only hard-rejects nuclear patterns.
var catastrophicSegmentPatterns = []*regexp.Regexp{
	// rm -rf / (trailing whitespace or end)
	regexp.MustCompile(`^\s*(?:sudo\s+)?rm\s+(?:-[a-zA-Z]*[rRfF][a-zA-Z]*\s+)+/\s*$`),
	// rm -rf /* / rm -rf /anything-at-root (glob pattern or bare path at root)
	regexp.MustCompile(`^\s*(?:sudo\s+)?rm\s+(?:-[a-zA-Z]*[rRfF][a-zA-Z]*\s+)+/\*`),
	// rm -rf ~ / ~/ / ~/* / $HOME / ${HOME} / $HOME/ / $HOME/*
	regexp.MustCompile(`^\s*(?:sudo\s+)?rm\s+(?:-[a-zA-Z]*[rRfF][a-zA-Z]*\s+)+(?:~|~/|~/\*|\$HOME|\$\{HOME\}|\$HOME/|\$HOME/\*)\s*$`),
	// Fork bomb
	regexp.MustCompile(`:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:`),
	// dd writing to a whole block device
	regexp.MustCompile(`^\s*(?:sudo\s+)?dd\b[^;&|]*\bof=/dev/(?:sd[a-z]|nvme\d+n\d+|disk\d+)\b`),
	// mkfs against a real device
	regexp.MustCompile(`^\s*(?:sudo\s+)?mkfs(?:\.[a-zA-Z0-9]+)?\s+/dev/(?:sd[a-z]|nvme\d+n\d+|disk\d+)\b`),
	// Shell-redirect overwrite of a block device
	regexp.MustCompile(`>\s*/dev/(?:sd[a-z]|nvme\d+n\d+|disk\d+)\b`),
}

// segmentSeparators splits a command string into top-level segments.
// Imperfect (doesn't respect quoting), but good enough to eliminate the
// common false positives where dangerous text appears inside quotes or
// as an argument to echo/printf.
var segmentSeparators = regexp.MustCompile(`[;\n]|&&|\|\||\|`)

// forkBombPattern matches the classic :(){ :|:& };: shell fork bomb.
// We run this against the full command because its internal `|` and `;`
// would otherwise fragment it.
var forkBombPattern = regexp.MustCompile(`:\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:`)

// IsCatastrophic reports whether cmd contains any catastrophic invocation.
// Exported so other layers (server API, future REST endpoints) can reuse
// the policy.
func IsCatastrophic(cmd string) bool {
	if forkBombPattern.MatchString(cmd) {
		return true
	}
	for _, seg := range segmentSeparators.Split(cmd, -1) {
		seg = strings.TrimSpace(seg)
		if seg == "" {
			continue
		}
		for _, re := range catastrophicSegmentPatterns {
			if re.MatchString(seg) {
				return true
			}
		}
	}
	return false
}

// NewBash constructs the bash tool. The tool runs commands without prompting
// (yolo-by-default). Commands matching IsCatastrophic are rejected outright.
// approve is retained in the signature for future use (e.g., plugin-installed
// tools that want their own approval layer) but the built-in bash never calls
// it.
func NewBash(approve ApprovalFn) Tool { return &bashTool{} }

type bashTool struct{}

func (*bashTool) Name() string     { return "bash" }
func (*bashTool) Label() string    { return "Run shell command" }
func (*bashTool) Category() string { return CategoryBuiltin }
func (*bashTool) IsReadOnly() bool { return false }
func (*bashTool) Description() string {
	return "Execute a shell command with bash -lc. Returns combined stdout+stderr. Use for compilation, tests, git operations, searches, anything scriptable."
}

func (*bashTool) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"command": map[string]any{
				"type":        "string",
				"description": "Shell command to execute. Runs via bash -lc.",
			},
			"timeout_seconds": map[string]any{
				"type":        "integer",
				"description": "Optional timeout in seconds. Default 120.",
				"default":     120,
			},
		},
		"required": []string{"command"},
	}
}

func (*bashTool) Execute(ctx context.Context, args map[string]any, onUpdate UpdateFn) (Result, error) {
	cmdStr, _ := args["command"].(string)
	if strings.TrimSpace(cmdStr) == "" {
		return Result{Content: "error: empty command", IsError: true}, nil
	}

	if IsCatastrophic(cmdStr) {
		return Result{
			Content: "refused: command matches a catastrophic pattern (root delete, home wipe, fork bomb, or block-device overwrite). This policy cannot be overridden from inside the agent.",
			IsError: true,
		}, nil
	}

	timeout := 120 * time.Second
	if v, ok := args["timeout_seconds"].(float64); ok && v > 0 {
		timeout = time.Duration(v) * time.Second
	}

	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(runCtx, "bash", "-lc", cmdStr)
	// Kill the whole process group on timeout/cancel, and give children a short
	// grace window to drain the pipe before Wait gives up on them.
	procutil.SetupProcessGroup(cmd)
	cmd.WaitDelay = 2 * time.Second

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return Result{}, err
	}
	cmd.Stderr = cmd.Stdout

	if err := cmd.Start(); err != nil {
		return Result{Content: fmt.Sprintf("start failed: %v", err), IsError: true}, nil
	}

	var (
		mu  sync.Mutex
		buf strings.Builder
	)

	flushCh := make(chan struct{}, 1)
	doneCh := make(chan struct{})
	go func() {
		ticker := time.NewTicker(50 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-doneCh:
				return
			case <-ticker.C:
				select {
				case flushCh <- struct{}{}:
				default:
				}
			}
		}
	}()
	go func() {
		lastEmitted := 0
		for {
			select {
			case <-doneCh:
				return
			case <-flushCh:
				mu.Lock()
				current := buf.String()
				mu.Unlock()
				if len(current) > lastEmitted && onUpdate != nil {
					onUpdate(Result{Content: truncateForDisplay(current)})
					lastEmitted = len(current)
				}
			}
		}
	}()

	reader := bufio.NewReader(stdout)
	capped := false
	for {
		chunk := make([]byte, 4096)
		n, rerr := reader.Read(chunk)
		if n > 0 {
			mu.Lock()
			if !capped {
				if buf.Len()+n > maxBashCapture {
					buf.Write(chunk[:maxBashCapture-buf.Len()])
					buf.WriteString(fmt.Sprintf("\n... [output capped at %d bytes; remainder discarded]", maxBashCapture))
					capped = true
				} else {
					buf.Write(chunk[:n])
				}
			}
			// Once capped we keep reading (below) to drain the pipe but stop
			// appending, bounding memory regardless of how much the command emits.
			mu.Unlock()
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			break
		}
	}

	waitErr := cmd.Wait()
	close(doneCh)

	output := buf.String()
	if runCtx.Err() == context.DeadlineExceeded {
		return Result{Content: output + fmt.Sprintf("\n[timed out after %s]", timeout), IsError: true}, nil
	}
	if waitErr != nil {
		exitCode := -1
		if exitErr, ok := waitErr.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		}
		return Result{
			Content: output + fmt.Sprintf("\n[exit %d]", exitCode),
			Details: map[string]any{"exit_code": exitCode},
			IsError: true,
		}, nil
	}
	return Result{Content: output, Details: map[string]any{"exit_code": 0}}, nil
}

func truncateForDisplay(s string) string {
	const max = 8192
	if len(s) <= max {
		return s
	}
	return s[:max] + fmt.Sprintf("\n... (%d bytes truncated)", len(s)-max)
}
