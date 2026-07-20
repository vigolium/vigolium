// Package fuzz is a low-level, agent-driven fuzzing primitive: inject a
// caller-supplied payload set into chosen positions of a single HTTP request,
// send each variant, and report per-payload response signals (status, size,
// words, lines, time, reflection, baseline delta) with match/filter gating.
//
// It is deliberately NOT a scanner. It makes no decision about *what* to test
// and emits no findings — the caller (a coding agent, or the vigolium module
// scanner) brings the intelligence; fuzz provides a fast, scope-aware,
// controllable send+observe loop. For opinionated, confirmation-backed
// vulnerability detection use the module scanner (`vigolium scan-request -m ...`)
// instead; fuzz reports raw signals for the caller to reason over.
//
// The send path, request parsing, and response hashing are reused verbatim from
// pkg/replay (replay.SendRaw); positions are resolved through pkg/httpmsg
// insertion points, so the byte-level injection matches what the module scanner
// does.
package fuzz

import (
	gohttp "net/http"
	"regexp"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// positionKind distinguishes how a payload is injected at a Position.
type positionKind int

const (
	// kindInsertionPoint uses an httpmsg.InsertionPoint (param/header/cookie/
	// param-name) — structured injection with correct Content-Length handling.
	kindInsertionPoint positionKind = iota
	// kindMarker replaces a literal keyword (default "FUZZ") anywhere in the
	// raw request, including the request line and path — no insertion point
	// needed. Content-Length is recomputed best-effort when a body is present.
	kindMarker
	// kindMethod rewrites the request-line verb (there is no INS_* type for
	// the method token).
	kindMethod
)

// Position is one place a payload gets injected. Exactly one injection
// mechanism backs it (insertion point, literal marker, or method rewrite).
type Position struct {
	// Name identifies the position: the parameter/header/cookie name for
	// insertion points, the keyword for markers, or "method".
	Name string
	// Label is a stable, human/agent-readable position type, e.g.
	// "URL_PARAM", "HEADER", "COOKIE", "MARKER", "METHOD".
	Label string
	// Base is the original value at this position (empty for markers/method).
	Base string

	kind positionKind
	ip   httpmsg.InsertionPoint // set when kind == kindInsertionPoint
}

// Matchers keep a response when it satisfies at least one configured category
// (OR across categories). An empty Matchers matches everything — the primitive
// default, leaning on Filters + auto-calibration to remove noise rather than an
// opinionated status allowlist.
type Matchers struct {
	AllStatus bool // -mc all
	Status    []int
	Sizes     []int
	Words     []int
	Lines     []int
	Regex     *regexp.Regexp // -mr, matched against the response body
	TimeMs    int64          // -mt, response time >= this many ms
}

// configured reports whether any matcher category is set.
func (m Matchers) configured() bool {
	return m.AllStatus || len(m.Status) > 0 || len(m.Sizes) > 0 || len(m.Words) > 0 ||
		len(m.Lines) > 0 || m.Regex != nil || m.TimeMs > 0
}

// Filters drop a response when it matches any configured category (OR).
type Filters struct {
	Status []int
	Sizes  []int
	Words  []int
	Lines  []int
	Regex  *regexp.Regexp
	TimeMs int64
}

func (f Filters) configured() bool {
	return len(f.Status) > 0 || len(f.Sizes) > 0 || len(f.Words) > 0 ||
		len(f.Lines) > 0 || f.Regex != nil || f.TimeMs > 0
}

// Baseline is the un-fuzzed request's response, used for delta reporting and
// as the seed for auto-calibration.
type Baseline struct {
	Status int    `json:"status"`
	Length int    `json:"length"`
	Words  int    `json:"words"`
	Lines  int    `json:"lines"`
	Hash   string `json:"content_hash,omitempty"`
	Error  string `json:"error,omitempty"`
}

// Result is the outcome of sending one payload at one position. It is the unit
// streamed as JSONL — each line is self-describing (position + payload), so
// results need no ordering guarantee under concurrency.
type Result struct {
	Position     string `json:"position"`
	PositionType string `json:"position_type"`
	Payload      string `json:"payload"`

	Status      int    `json:"status"`
	Length      int    `json:"length"`
	Words       int    `json:"words"`
	Lines       int    `json:"lines"`
	TimeMs      int64  `json:"time_ms"`
	ContentHash string `json:"content_hash,omitempty"`

	// Reflected is true when the payload bytes appear verbatim in the
	// response body (a cheap, honest signal — not a vulnerability verdict).
	Reflected bool `json:"reflected"`

	// Signals vs the baseline response.
	StatusChanged bool `json:"status_changed"`
	LengthDelta   int  `json:"length_delta"`

	// Matched is true when the result passed the matcher/filter gate and was
	// not suppressed by auto-calibration — i.e. the caller asked to see it.
	Matched bool `json:"matched"`
	// Calibrated is true when auto-calibration classified the response as a
	// wildcard/catch-all and suppressed it. Surfaced (not hidden) so the
	// agent can tell "filtered by me" from "looked like the catch-all".
	Calibrated bool `json:"calibrated,omitempty"`

	Error string `json:"error,omitempty"`
}

// Report is the aggregate returned by Run once every send completes.
type Report struct {
	Baseline   Baseline `json:"baseline"`
	Sent       int      `json:"sent"`
	Matched    int      `json:"matched"`
	Calibrated int      `json:"calibrated"`
	Errors     int      `json:"errors"`
}

// Job fully describes one fuzz run. Network policy (client, proxy, timeout,
// redirects) is the caller's — fuzz does not construct clients, mirroring
// pkg/replay.
type Job struct {
	Raw      []byte
	Scheme   string
	Hostname string
	Port     int

	Positions []Position
	Payloads  []string

	Matchers Matchers
	Filters  Filters
	// AutoCalibrate learns the target's wildcard/catch-all response signature
	// from a few improbable probe values and suppresses matching results. This
	// is the primitive's one concession to the catch-all FP problem; it never
	// promotes a result to a finding, only demotes noise.
	AutoCalibrate bool

	Client      *gohttp.Client
	NoRedirects bool
	ExcerptCap  int

	Concurrency int
	DelayMs     int

	// OnResult, if set, is called once per send as results complete. It is
	// invoked from multiple goroutines; the callback must be safe to call
	// concurrently (the CLI serializes it behind a mutex).
	OnResult func(Result)
}
