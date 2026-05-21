package claudecost

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Summary is the aggregated result for one vigolium-audit run.
type Summary struct {
	// Model is the model ID reported by the main session's init event
	// (e.g. "claude-opus-4-7[1m]"). Empty when the JSONL had no init.
	Model string `json:"model,omitempty"`

	// SessionID is the session UUID from the main stream's init event.
	// Used downstream to locate subagent JSONL files.
	SessionID string `json:"session_id,omitempty"`

	// CWD is the working directory recorded on the main stream's init
	// event. Used downstream to derive the subagent task directory.
	CWD string `json:"cwd,omitempty"`

	// Main is the usage for the parent audit agent session.
	Main Usage `json:"main"`

	// MainCostReported is `result.total_cost_usd` as reported by the
	// Claude CLI for the main session. Zero when absent.
	MainCostReported float64 `json:"main_cost_reported,omitempty"`

	// Subagents lists per-subagent usage for every async-agent transcript
	// found alongside this run.
	Subagents []SubagentUsage `json:"subagents,omitempty"`

	// TotalCostUSD is the sum of (Main priced locally) + (each subagent
	// priced locally). We use locally-priced main rather than
	// MainCostReported so main + subagent totals are computed the same
	// way and remain self-consistent.
	TotalCostUSD float64 `json:"total_cost_usd"`
}

// SubagentUsage captures a single async-agent's token totals.
type SubagentUsage struct {
	AgentID string  `json:"agent_id"`
	Model   string  `json:"model,omitempty"`
	Usage   Usage   `json:"usage"`
	CostUSD float64 `json:"cost_usd"`
}

// ParseStreamFile reads a Claude stream-json transcript (audit-stream.jsonl
// for the main session, or a tasks/<agentId>.output file for a subagent)
// and returns the aggregated usage, the most recently reported model, and —
// for main-session files — the session_id, cwd, and reported total cost.
//
// Usage is aggregated by deduplicating assistant messages on message.id and
// keeping the final (highest output_tokens) usage per id, because Claude's
// stream-json reports cumulative usage within a single message rather than
// per-delta deltas.
func ParseStreamFile(path string) (Usage, string, string, string, float64, error) {
	f, err := os.Open(path)
	if err != nil {
		return Usage{}, "", "", "", 0, err
	}
	defer func() { _ = f.Close() }()
	return parseStream(f)
}

// envelope is the minimal shape we care about. Kept local to avoid coupling
// with the claudestream renderer package.
type envelope struct {
	Type    string          `json:"type"`
	Subtype string          `json:"subtype"`
	Message json.RawMessage `json:"message"`

	// system.init fields
	SessionID string `json:"session_id"`
	CWD       string `json:"cwd"`
	Model     string `json:"model"`

	// result fields
	TotalCostUSD float64 `json:"total_cost_usd"`
}

type streamMessage struct {
	ID    string      `json:"id"`
	Model string      `json:"model"`
	Usage streamUsage `json:"usage"`
}

type streamUsage struct {
	InputTokens              int64          `json:"input_tokens"`
	OutputTokens             int64          `json:"output_tokens"`
	CacheReadInputTokens     int64          `json:"cache_read_input_tokens"`
	CacheCreationInputTokens int64          `json:"cache_creation_input_tokens"`
	CacheCreation            *cacheCreation `json:"cache_creation,omitempty"`
}

type cacheCreation struct {
	Ephemeral5mInputTokens int64 `json:"ephemeral_5m_input_tokens"`
	Ephemeral1hInputTokens int64 `json:"ephemeral_1h_input_tokens"`
}

func parseStream(r io.Reader) (Usage, string, string, string, float64, error) {
	// Dedupe on message.id — keep the highest output_tokens seen, which is
	// the final cumulative usage for that message.
	per := make(map[string]streamUsage)
	var model, sessionID, cwd string
	var reportedCost float64

	scanner := bufio.NewScanner(r)
	buf := make([]byte, 0, 1<<20)
	scanner.Buffer(buf, 16<<20)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		var env envelope
		if err := json.Unmarshal(line, &env); err != nil {
			continue
		}
		switch env.Type {
		case "system":
			if env.Subtype == "init" {
				if sessionID == "" {
					sessionID = env.SessionID
				}
				if cwd == "" {
					cwd = env.CWD
				}
				if env.Model != "" {
					model = env.Model
				}
			}
		case "assistant":
			var msg streamMessage
			if err := json.Unmarshal(env.Message, &msg); err != nil {
				continue
			}
			if msg.Model != "" {
				model = msg.Model
			}
			if msg.ID == "" {
				continue
			}
			prev, ok := per[msg.ID]
			if !ok || msg.Usage.OutputTokens > prev.OutputTokens {
				per[msg.ID] = msg.Usage
			}
		case "result":
			if env.TotalCostUSD > 0 {
				reportedCost = env.TotalCostUSD
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return Usage{}, model, sessionID, cwd, reportedCost, fmt.Errorf("scan stream: %w", err)
	}

	var total Usage
	for _, u := range per {
		total.InputTokens += u.InputTokens
		total.OutputTokens += u.OutputTokens
		total.CacheReadTokens += u.CacheReadInputTokens
		total.CacheCreateTokens += u.CacheCreationInputTokens
		if u.CacheCreation != nil {
			total.CacheCreate5mTokens += u.CacheCreation.Ephemeral5mInputTokens
			total.CacheCreate1hTokens += u.CacheCreation.Ephemeral1hInputTokens
		}
	}
	return total, model, sessionID, cwd, reportedCost, nil
}

// SubagentTasksDir returns the directory where Claude CLI writes async-agent
// transcripts for a given main session. Claude uses /tmp/claude-<uid>/<cwd>/
// <session_id>/tasks/, where <cwd> is the working directory with every '/'
// replaced by '-'. Returns "" when uid, cwd, or sessionID is empty.
func SubagentTasksDir(uid int, cwd, sessionID string) string {
	if cwd == "" || sessionID == "" {
		return ""
	}
	escaped := strings.ReplaceAll(cwd, "/", "-")
	return filepath.Join("/tmp", fmt.Sprintf("claude-%d", uid), escaped, sessionID, "tasks")
}

// FindSubagentFiles enumerates Claude async-agent transcripts under the
// main session's tasks directory. Each returned path is a JSONL file whose
// first line carries an "agentId" field — this distinguishes real async
// agents from plain Bash-tool background task outputs (which share the same
// directory but have no agentId).
func FindSubagentFiles(tasksDir string) ([]string, error) {
	if tasksDir == "" {
		return nil, nil
	}
	entries, err := os.ReadDir(tasksDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".output") {
			continue
		}
		path := filepath.Join(tasksDir, e.Name())
		if hasAgentID(path) {
			out = append(out, path)
		}
	}
	return out, nil
}

// hasAgentID returns true when the first non-empty line of path has a
// non-empty "agentId" field. Used to filter async-agent transcripts from
// bash-background task outputs in the same directory.
func hasAgentID(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	scanner := bufio.NewScanner(f)
	buf := make([]byte, 0, 1<<20)
	scanner.Buffer(buf, 16<<20)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var probe struct {
			AgentID string `json:"agentId"`
		}
		if err := json.Unmarshal(line, &probe); err != nil {
			return false
		}
		return probe.AgentID != ""
	}
	return false
}

// parseSubagentAgentID returns the agentId reported in the first JSONL line.
func parseSubagentAgentID(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()
	scanner := bufio.NewScanner(f)
	buf := make([]byte, 0, 1<<20)
	scanner.Buffer(buf, 16<<20)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var probe struct {
			AgentID string `json:"agentId"`
		}
		if err := json.Unmarshal(line, &probe); err != nil {
			return ""
		}
		return probe.AgentID
	}
	return ""
}

// BuildSummary parses the main session transcript at mainPath, locates the
// corresponding subagent transcripts using uid and the init event's cwd +
// session_id, and returns a fully-priced Summary.
//
// Errors from missing subagent directories are swallowed — subagents are
// optional and absence means the run simply had none. Errors from the main
// transcript bubble up.
func BuildSummary(mainPath string, uid int) (Summary, error) {
	main, model, sessionID, cwd, reportedCost, err := ParseStreamFile(mainPath)
	if err != nil {
		return Summary{}, err
	}
	tasksDir := SubagentTasksDir(uid, cwd, sessionID)
	return buildSummaryFromParts(main, model, sessionID, cwd, reportedCost, tasksDir), nil
}

// BuildSummaryWithTasksDir is the injectable-tasks-dir variant of
// BuildSummary. Callers that know where the async-agent transcripts live
// (tests, or deployments where Claude CLI's tmp layout differs from the
// default) can pass it directly instead of relying on uid/cwd/session
// derivation.
func BuildSummaryWithTasksDir(mainPath, tasksDir string) (Summary, error) {
	main, model, sessionID, cwd, reportedCost, err := ParseStreamFile(mainPath)
	if err != nil {
		return Summary{}, err
	}
	return buildSummaryFromParts(main, model, sessionID, cwd, reportedCost, tasksDir), nil
}

// buildSummaryFromParts shares the pricing and subagent-enumeration logic
// between BuildSummary and BuildSummaryWithTasksDir.
func buildSummaryFromParts(main Usage, model, sessionID, cwd string, reportedCost float64, tasksDir string) Summary {
	// Prefer the CLI's own total_cost_usd for the main session when
	// present — it's computed by the Claude CLI and reflects the actual
	// pricing schedule in use. Fall back to local pricing when the
	// transcript was truncated or the result event was missing.
	mainCost := reportedCost
	if mainCost == 0 {
		mainCost = main.Price(model)
	}
	s := Summary{
		Model:            model,
		SessionID:        sessionID,
		CWD:              cwd,
		Main:             main,
		MainCostReported: reportedCost,
		TotalCostUSD:     mainCost,
	}

	files, ferr := FindSubagentFiles(tasksDir)
	if ferr != nil {
		// Non-fatal — return what we have.
		return s
	}
	for _, path := range files {
		usage, sm, _, _, _, perr := ParseStreamFile(path)
		if perr != nil {
			continue
		}
		subModel := sm
		if subModel == "" {
			subModel = model
		}
		cost := usage.Price(subModel)
		s.Subagents = append(s.Subagents, SubagentUsage{
			AgentID: parseSubagentAgentID(path),
			Model:   subModel,
			Usage:   usage,
			CostUSD: cost,
		})
		s.TotalCostUSD += cost
	}
	return s
}
