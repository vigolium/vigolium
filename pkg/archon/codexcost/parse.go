package codexcost

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Summary captures the fully-priced cost accounting for one Codex audit run.
type Summary struct {
	// SessionID is the Codex session UUID from session_meta.payload.id.
	SessionID string `json:"session_id,omitempty"`

	// Model is what Codex reported in turn_context.payload.model — e.g.
	// "gpt-5.4". Empty when no turn_context was seen.
	Model string `json:"model,omitempty"`

	// CWD is the working directory recorded on session_meta.
	CWD string `json:"cwd,omitempty"`

	// RolloutPath is the absolute path to the rollout JSONL file this
	// summary was built from. Useful for debugging.
	RolloutPath string `json:"rollout_path,omitempty"`

	// Usage is the final cumulative total_token_usage from the last
	// token_count event in the rollout.
	Usage Usage `json:"usage"`

	// TotalCostUSD is Usage priced against Model's pricing table.
	TotalCostUSD float64 `json:"total_cost_usd"`
}

// CodexHome returns the directory Codex uses for persistent state.
// Honors $CODEX_HOME, otherwise ~/.codex/.
func CodexHome() string {
	if v := os.Getenv("CODEX_HOME"); v != "" {
		return v
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, ".codex")
}

// rolloutSessionMeta is the subset of session_meta we need to match a
// rollout to an archon run (by cwd + start time).
type rolloutSessionMeta struct {
	Type    string `json:"type"`
	Payload struct {
		ID        string `json:"id"`
		Timestamp string `json:"timestamp"`
		CWD       string `json:"cwd"`
	} `json:"payload"`
}

// turnContextMeta is the subset of turn_context we need for the model id.
type turnContextMeta struct {
	Type    string `json:"type"`
	Payload struct {
		Model string `json:"model"`
	} `json:"payload"`
}

// tokenCountMeta is the subset of token_count events we need.
type tokenCountMeta struct {
	Type    string `json:"type"`
	Payload struct {
		Type string `json:"type"`
		Info struct {
			TotalTokenUsage Usage `json:"total_token_usage"`
		} `json:"info"`
	} `json:"payload"`
}

// FindRollout locates the rollout JSONL file for a Codex run that started
// at approximately startedAt with working directory cwd. Returns "" when
// no plausible rollout is found.
//
// Matching rules (in order of preference):
//  1. session_meta.payload.cwd matches cwd exactly, AND session_meta.timestamp
//     is within ±5 min of startedAt.
//  2. On tie, prefer the file whose timestamp is closest to startedAt.
//
// Only files under the last 3 dated subdirectories are scanned, which
// covers normal cases (run completes same day it started) and the
// around-midnight case without walking the entire session history.
func FindRollout(codexHome, cwd string, startedAt time.Time) (string, error) {
	if codexHome == "" || cwd == "" {
		return "", nil
	}
	base := filepath.Join(codexHome, "sessions")
	if _, err := os.Stat(base); err != nil {
		return "", nil
	}

	// Gather candidate date directories for startedAt ± 1 day.
	dateDirs := candidateDateDirs(base, startedAt)

	var bestPath string
	var bestDelta time.Duration
	found := false
	for _, dir := range dateDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".jsonl") {
				continue
			}
			path := filepath.Join(dir, e.Name())
			meta := readSessionMeta(path)
			if meta == nil || meta.Payload.CWD != cwd {
				continue
			}
			ts, err := time.Parse(time.RFC3339Nano, meta.Payload.Timestamp)
			if err != nil {
				continue
			}
			delta := ts.Sub(startedAt)
			if delta < 0 {
				delta = -delta
			}
			if delta > 5*time.Minute {
				continue
			}
			if !found || delta < bestDelta {
				bestPath = path
				bestDelta = delta
				found = true
			}
		}
	}
	return bestPath, nil
}

// candidateDateDirs returns the three YYYY/MM/DD directories most likely
// to contain a rollout started at startedAt (yesterday, today, tomorrow
// in startedAt's local date). Non-existent dirs are included — the caller
// simply skips them on ReadDir failure.
func candidateDateDirs(base string, startedAt time.Time) []string {
	out := make([]string, 0, 3)
	for offset := -1; offset <= 1; offset++ {
		d := startedAt.AddDate(0, 0, offset)
		out = append(out, filepath.Join(base,
			fmt.Sprintf("%04d", d.Year()),
			fmt.Sprintf("%02d", int(d.Month())),
			fmt.Sprintf("%02d", d.Day())))
	}
	return out
}

// readSessionMeta returns the first JSONL line parsed as session_meta,
// or nil when the file isn't a Codex rollout or its first line isn't
// session_meta.
func readSessionMeta(path string) *rolloutSessionMeta {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()
	scanner := bufio.NewScanner(f)
	buf := make([]byte, 0, 1<<20)
	scanner.Buffer(buf, 16<<20)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		var meta rolloutSessionMeta
		if err := json.Unmarshal(line, &meta); err != nil {
			return nil
		}
		if meta.Type != "session_meta" {
			return nil
		}
		return &meta
	}
	return nil
}

// ParseRollout walks the rollout JSONL and extracts (session_id, model,
// cwd, final cumulative usage). The final usage is the total_token_usage
// of the last token_count event — Codex reports these cumulatively so
// the final one is authoritative for the whole run.
func ParseRollout(path string) (sessionID, model, cwd string, usage Usage, err error) {
	f, ferr := os.Open(path)
	if ferr != nil {
		return "", "", "", Usage{}, ferr
	}
	defer func() { _ = f.Close() }()
	sid, m, c, u, perr := parseRollout(f)
	if perr != nil {
		return "", "", "", Usage{}, perr
	}
	return sid, m, c, u, nil
}

func parseRollout(r io.Reader) (sessionID, model, cwd string, usage Usage, err error) {
	scanner := bufio.NewScanner(r)
	buf := make([]byte, 0, 1<<20)
	scanner.Buffer(buf, 16<<20)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		// Peek at type so we can route to the right decoder.
		var probe struct {
			Type string `json:"type"`
		}
		if jerr := json.Unmarshal(line, &probe); jerr != nil {
			continue
		}
		switch probe.Type {
		case "session_meta":
			var meta rolloutSessionMeta
			if jerr := json.Unmarshal(line, &meta); jerr == nil {
				if sessionID == "" {
					sessionID = meta.Payload.ID
				}
				if cwd == "" {
					cwd = meta.Payload.CWD
				}
			}
		case "turn_context":
			var tc turnContextMeta
			if jerr := json.Unmarshal(line, &tc); jerr == nil && tc.Payload.Model != "" {
				model = tc.Payload.Model
			}
		case "event_msg":
			var tc tokenCountMeta
			if jerr := json.Unmarshal(line, &tc); jerr == nil && tc.Payload.Type == "token_count" {
				// Token_count events carry cumulative totals, so each
				// one can overwrite the previous. The last one wins.
				usage = tc.Payload.Info.TotalTokenUsage
			}
		}
	}
	if scanErr := scanner.Err(); scanErr != nil {
		return "", "", "", Usage{}, fmt.Errorf("scan rollout: %w", scanErr)
	}
	return sessionID, model, cwd, usage, nil
}

// BuildSummary locates the Codex rollout for a run started at startedAt
// with working directory cwd, parses it, and returns a priced Summary.
// Returns a zero-valued Summary with no error when no rollout can be
// located — the caller should treat that as "unknown cost".
func BuildSummary(cwd string, startedAt time.Time) (Summary, error) {
	codexHome := CodexHome()
	if codexHome == "" {
		return Summary{}, nil
	}
	rolloutPath, err := FindRollout(codexHome, cwd, startedAt)
	if err != nil {
		return Summary{}, err
	}
	if rolloutPath == "" {
		return Summary{}, nil
	}
	sessionID, model, rolloutCWD, usage, parseErr := ParseRollout(rolloutPath)
	if parseErr != nil {
		return Summary{}, parseErr
	}
	// Safety: an empty usage from a zero-progress run still yields a
	// meaningful $0 summary (rather than claiming a rollout we couldn't
	// parse at all), so we return what we have.
	s := Summary{
		SessionID:    sessionID,
		Model:        model,
		CWD:          rolloutCWD,
		RolloutPath:  rolloutPath,
		Usage:        usage,
		TotalCostUSD: usage.Price(model),
	}
	return s, nil
}

