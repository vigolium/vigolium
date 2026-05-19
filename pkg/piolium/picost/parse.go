// Package picost extracts the priced cost of a piolium audit run by
// reading Pi's per-cwd session transcripts.
//
// Pi (the @earendil-works/pi-coding-agent runtime piolium runs on top of)
// stores one JSONL transcript per pi-process invocation under
// `~/.pi/agent/sessions/<encoded-cwd>/<timestamp>_<sessionid>.jsonl`,
// where the cwd encoding is `--<path>--` with `/` replaced by `-`.
// Every assistant `message` event in the transcript carries a `usage`
// payload that includes a pre-computed `cost` (USD) alongside the token
// counts. We sum across all session files newer than the audit's
// startedAt to produce the run-level summary.
//
// Unlike codexcost / claudecost, picost does NOT need its own pricing
// table — Pi has already priced each turn against the active provider's
// rates by the time the message lands in the transcript.
package picost

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// matchSlackBefore is how far before startedAt we still consider a
// session file to belong to this run. Pi writes the session timestamp
// before the first assistant message, and the audit's startedAt is
// captured slightly after `pi` is launched, so allow a small skew.
const matchSlackBefore = 30 * time.Second

// matchSlackAfter is the upper bound on how long the audit can run
// before we stop attributing new sessions to it. 24h covers piolium's
// deepest mode.
const matchSlackAfter = 24 * time.Hour

// Usage is the run-level token total summed from every assistant message
// in every session file attributed to one piolium audit.
type Usage struct {
	Input       int64 `json:"input"`
	Output      int64 `json:"output"`
	CacheRead   int64 `json:"cacheRead"`
	CacheWrite  int64 `json:"cacheWrite"`
	TotalTokens int64 `json:"totalTokens"`
}

// Summary captures the priced cost of one piolium audit run.
type Summary struct {
	// Model is whichever model the last priced assistant message reported.
	// Mixed-model runs emit only the most recent name; the per-session
	// detail lives in Sessions.
	Model string `json:"model,omitempty"`

	// CWD is the audited directory (cmd.Dir for the pi subprocess).
	CWD string `json:"cwd,omitempty"`

	// SessionDir is the absolute path to the encoded cwd folder under
	// ~/.pi/agent/sessions/. Useful for debugging.
	SessionDir string `json:"session_dir,omitempty"`

	// Sessions enumerates the per-file contributions, in time order.
	Sessions []SessionSummary `json:"sessions,omitempty"`

	// Usage is the total across every Sessions entry.
	Usage Usage `json:"usage"`

	// TotalCostUSD is summed from each session's reported per-message
	// usage.cost.total. Pi computes the price; we just add.
	TotalCostUSD float64 `json:"total_cost_usd"`
}

// SessionSummary describes one Pi session file's contribution.
type SessionSummary struct {
	Path      string    `json:"path"`
	SessionID string    `json:"session_id,omitempty"`
	Model     string    `json:"model,omitempty"`
	StartedAt time.Time `json:"started_at"`
	Usage     Usage     `json:"usage"`
	CostUSD   float64   `json:"cost_usd"`
}

// EncodeSessionDir converts a cwd into the directory name Pi uses under
// `~/.pi/agent/sessions/`. Pi prepends and appends "--" and replaces
// every "/" in the path with "-". The leading "/" of the absolute path
// becomes the third dash of the "--" prefix:
//
//	/Users/j3ssie/Desktop/vuln-apps/VAmPI
//	→ --Users-j3ssie-Desktop-vuln-apps-VAmPI--
func EncodeSessionDir(cwd string) string {
	trimmed := strings.Trim(cwd, "/")
	if trimmed == "" {
		return "----"
	}
	return "--" + strings.ReplaceAll(trimmed, "/", "-") + "--"
}

// PiHome returns ~/.pi by default, honoring $PI_HOME for tests.
func PiHome() string {
	if v := os.Getenv("PI_HOME"); v != "" {
		return v
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, ".pi")
}

// SessionsRoot is the per-cwd parent under PiHome.
func SessionsRoot() string {
	home := PiHome()
	if home == "" {
		return ""
	}
	return filepath.Join(home, "agent", "sessions")
}

// piTranscriptLine matches the union of the transcript lines we care about
// — the `session` header (first line) and any assistant `message` event.
// Other types (`model_change`, `thinking_level_change`, …) are ignored.
type piTranscriptLine struct {
	Type      string `json:"type"`
	ID        string `json:"id,omitempty"`
	Timestamp string `json:"timestamp,omitempty"`
	CWD       string `json:"cwd,omitempty"`
	Message   struct {
		Role     string `json:"role"`
		Provider string `json:"provider,omitempty"`
		Model    string `json:"model,omitempty"`
		Usage    *struct {
			Input       int64 `json:"input"`
			Output      int64 `json:"output"`
			CacheRead   int64 `json:"cacheRead"`
			CacheWrite  int64 `json:"cacheWrite"`
			TotalTokens int64 `json:"totalTokens"`
			Cost        struct {
				Input      float64 `json:"input"`
				Output     float64 `json:"output"`
				CacheRead  float64 `json:"cacheRead"`
				CacheWrite float64 `json:"cacheWrite"`
				Total      float64 `json:"total"`
			} `json:"cost"`
		} `json:"usage,omitempty"`
	} `json:"message,omitempty"`
}

// scanSession opens path once and extracts the session header timestamp/id
// plus the summed usage and priced cost across every assistant message.
// Returns ok=false when path isn't a Pi session transcript (no `session`
// header on the first non-blank line).
func scanSession(path string) (sessionID string, startedAt time.Time, usage Usage, costUSD float64, model string, ok bool) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	buf := make([]byte, 0, 1<<20)
	scanner.Buffer(buf, 16<<20)

	headerSeen := false
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		var env piTranscriptLine
		if jerr := json.Unmarshal(line, &env); jerr != nil {
			continue
		}
		if !headerSeen {
			if env.Type != "session" {
				return
			}
			headerSeen = true
			sessionID = env.ID
			ts, terr := time.Parse(time.RFC3339Nano, env.Timestamp)
			if terr != nil {
				ts, terr = time.Parse(time.RFC3339, env.Timestamp)
				if terr != nil {
					return
				}
			}
			startedAt = ts
			continue
		}
		if env.Type != "message" || env.Message.Role != "assistant" || env.Message.Usage == nil {
			continue
		}
		u := env.Message.Usage
		usage.Input += u.Input
		usage.Output += u.Output
		usage.CacheRead += u.CacheRead
		usage.CacheWrite += u.CacheWrite
		usage.TotalTokens += u.TotalTokens
		costUSD += u.Cost.Total
		if env.Message.Model != "" {
			model = env.Message.Model
		}
	}
	if err := scanner.Err(); err != nil {
		return "", time.Time{}, Usage{}, 0, "", false
	}
	ok = headerSeen
	return
}

// BuildSummary locates every Pi session transcript under the encoded-cwd
// directory whose `session` header timestamp is within
// [startedAt - matchSlackBefore, startedAt + matchSlackAfter] and sums
// their priced usage. Returns a zero summary (nil error) when no plausible
// transcript is found — callers should treat that as "unknown cost".
func BuildSummary(cwd string, startedAt time.Time) (Summary, error) {
	if cwd == "" {
		return Summary{}, nil
	}
	root := SessionsRoot()
	if root == "" {
		return Summary{}, nil
	}
	dir := filepath.Join(root, EncodeSessionDir(cwd))

	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return Summary{}, nil
		}
		return Summary{}, err
	}

	earliest := startedAt.Add(-matchSlackBefore)
	latest := startedAt.Add(matchSlackAfter)

	sessions := make([]SessionSummary, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".jsonl") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		sid, ts, usage, costUSD, model, ok := scanSession(path)
		if !ok {
			continue
		}
		if ts.Before(earliest) || ts.After(latest) {
			continue
		}
		// Skip 401-erroring sessions — Pi still writes a transcript but
		// no priced assistant turn lands.
		if usage.TotalTokens == 0 && costUSD == 0 {
			continue
		}
		sessions = append(sessions, SessionSummary{
			Path:      path,
			SessionID: sid,
			Model:     model,
			StartedAt: ts,
			Usage:     usage,
			CostUSD:   costUSD,
		})
	}

	if len(sessions) == 0 {
		return Summary{CWD: cwd, SessionDir: dir}, nil
	}

	sort.Slice(sessions, func(i, j int) bool {
		return sessions[i].StartedAt.Before(sessions[j].StartedAt)
	})

	var total Usage
	var totalCost float64
	var model string
	for _, s := range sessions {
		total.Input += s.Usage.Input
		total.Output += s.Usage.Output
		total.CacheRead += s.Usage.CacheRead
		total.CacheWrite += s.Usage.CacheWrite
		total.TotalTokens += s.Usage.TotalTokens
		totalCost += s.CostUSD
		if s.Model != "" {
			model = s.Model
		}
	}

	return Summary{
		Model:        model,
		CWD:          cwd,
		SessionDir:   dir,
		Sessions:     sessions,
		Usage:        total,
		TotalCostUSD: totalCost,
	}, nil
}
