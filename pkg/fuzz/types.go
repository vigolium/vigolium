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
	"context"
	gohttp "net/http"
	"regexp"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/replay"
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
	// kindAddHeader injects a header the request doesn't currently carry.
	// Headers like X-Forwarded-For or X-Original-URL are interesting to fuzz
	// precisely because the client never sends them, so requiring one to
	// already exist would rule out the whole class.
	kindAddHeader
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

// MatchMode selects how configured categories combine.
type MatchMode int

const (
	// MatchAny keeps/drops when at least one category matches (the default,
	// and what ffuf-style tools do).
	MatchAny MatchMode = iota
	// MatchAll requires every configured category to match, which is how you
	// express "a 200 *and* bigger than the baseline" without post-filtering.
	MatchAll
)

// HeaderMatcher tests one response header against a regex. An empty Value
// matches the header's mere presence.
type HeaderMatcher struct {
	Name  string
	Value *regexp.Regexp
}

// Criteria is a set of response tests. It backs both the keep set (Matchers)
// and the drop set (Filters), so the two can never drift in what they can
// express — a signal you can match on is always a signal you can exclude on.
type Criteria struct {
	AllStatus bool // --match-status-code all
	Status    NumPredicates
	Sizes     NumPredicates
	Words     NumPredicates
	Lines     NumPredicates
	TimeMs    NumPredicates
	Regex     *regexp.Regexp // matched against the response body
	Headers   []HeaderMatcher
	// TimeZ matches on standard deviations above the baseline mean rather
	// than absolute milliseconds.
	TimeZ NumPredicates
	Mode  MatchMode
}

// configured reports whether any category is set.
func (c Criteria) configured() bool {
	return c.AllStatus || !c.Status.Empty() || !c.Sizes.Empty() || !c.Words.Empty() ||
		!c.Lines.Empty() || !c.TimeMs.Empty() || !c.TimeZ.Empty() ||
		c.Regex != nil || len(c.Headers) > 0
}

// Matchers keep a response when it satisfies the configured categories. An
// empty Matchers matches everything — the primitive default, leaning on
// Filters + auto-calibration to remove noise rather than an opinionated status
// allowlist.
type Matchers = Criteria

// Filters drop a response when it satisfies the configured categories.
type Filters = Criteria

// Baseline is the un-fuzzed request's response, used for delta reporting and
// as the seed for auto-calibration.
type Baseline struct {
	Status int    `json:"status"`
	Length int    `json:"length"`
	Words  int    `json:"words"`
	Lines  int    `json:"lines"`
	Hash   string `json:"content_hash,omitempty"`
	Error  string `json:"error,omitempty"`

	// Timing statistics over Samples sends of the un-fuzzed request. A single
	// sample can't distinguish "this payload made the server work harder" from
	// "the network hiccuped", which is the whole difficulty of time-based
	// blind detection; a mean and a standard deviation can.
	TimeMs      int64   `json:"time_ms"`
	TimeStdDev  float64 `json:"time_stddev_ms,omitempty"`
	Samples     int     `json:"samples,omitempty"`
	TimeSamples []int64 `json:"time_samples,omitempty"`
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

	// Reflected is true when the payload appears in the response at all —
	// verbatim or in an escaped/encoded form (a cheap, honest signal, not a
	// vulnerability verdict).
	Reflected bool `json:"reflected"`
	// ReflectedRaw narrows that to a verbatim appearance. The distinction is
	// the whole game for injection classes: a payload echoed back HTML-escaped
	// is the application defending itself, and reporting it identically to an
	// unescaped echo is what buries the real signal.
	ReflectedRaw bool `json:"reflected_raw,omitempty"`
	// ReflectedIn names where it appeared: "body", or "header:Location".
	// Header reflection is invisible to body-only checks yet is exactly the
	// signal behind open redirect and response-splitting.
	ReflectedIn []string `json:"reflected_in,omitempty"`

	// Signals vs the baseline response.
	StatusChanged bool `json:"status_changed"`
	LengthDelta   int  `json:"length_delta"`
	// TimeZ is how many baseline standard deviations this response's time sits
	// above the baseline mean. It is what makes a time-based signal
	// expressible without hand-tuning a millisecond threshold per target:
	// --match-time-z 4 means "slower than this endpoint's own jitter
	// explains". Zero when the baseline wasn't sampled enough to have a
	// deviation.
	TimeZ float64 `json:"time_z,omitempty"`

	// AnomalyScore is the --anomaly detector's score for this response; 0
	// when detection is off. AnomalyReasons explains it.
	AnomalyScore   int             `json:"anomaly_score,omitempty"`
	AnomalyReasons []AnomalyReason `json:"anomaly_reasons,omitempty"`

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

	// Anomalies are the results the --anomaly detector flagged, scored
	// against the completed population and sorted most-interesting first.
	// Empty when detection is off.
	Anomalies []Result `json:"anomalies,omitempty"`
	// AnomaliesElided counts anomalies dropped by the report cap.
	AnomaliesElided int `json:"anomalies_elided,omitempty"`
}

// Job fully describes one fuzz run. Network policy (client, proxy, timeout,
// redirects) is the caller's — fuzz does not construct clients, mirroring
// pkg/replay.
type Job struct {
	Raw      []byte
	Scheme   string
	Hostname string
	Port     int

	// Positions and Payloads are the simple form: every position gets every
	// payload (sniper). Cases, when set, replaces them with an explicit plan —
	// which is how the multi-position modes express a send that varies several
	// markers at once.
	Positions []Position
	Payloads  []string
	Cases     []Case
	// Plan, when set, replaces Cases with a lazily-indexed plan (BuildPlan),
	// so a large sniper run never holds every case in memory.
	Plan CasePlan

	// AllowBaselineError lets a run proceed when every baseline sample
	// failed. Off by default: with no baseline, every delta, the calibration
	// seed and the anomaly detector compare against an empty response, so the
	// "signals" a run produces are artifacts of the failed baseline.
	AllowBaselineError bool

	Matchers Matchers
	Filters  Filters
	// BaselineSamples is how many times the un-fuzzed request is sent to build
	// the timing statistics. 1 (the default) skips deviation entirely.
	BaselineSamples int

	// Anomaly, when non-nil, turns on anomaly detection: each response is
	// scored against the baseline and against the run's own population, and
	// (when no explicit Matchers are set) the score replaces "keep everything"
	// as the gate. Detection retains response bodies until the run ends so it
	// can rescore against the finished population.
	Anomaly *AnomalyConfig

	// AutoCalibrate learns the target's wildcard/catch-all response signature
	// from a few improbable probe values and suppresses matching results. This
	// is the primitive's one concession to the catch-all FP problem; it never
	// promotes a result to a finding, only demotes noise.
	AutoCalibrate bool

	Client      *gohttp.Client
	NoRedirects bool
	ExcerptCap  int

	// Sender, when non-nil, replaces the default replay.SendRaw transport for
	// every send (baseline, calibration probes, and each payload variant). It
	// lets the caller route the exact request bytes through an external engine
	// (the Burp bridge) that preserves malformed requests. Must be safe for
	// concurrent use — the engine sends from up to Concurrency goroutines. When
	// set, Client is not required.
	Sender func(context.Context, []byte) *replay.Summary

	Concurrency int
	DelayMs     int
	// RateLimit caps the whole run at this many requests per second across
	// every worker, 0 = unlimited. It covers every send the run makes —
	// baseline samples and calibration probes as well as payloads — because a
	// WAF or a fragile target counts all of them. Smooth (burst 1), so a
	// limit of 20 never means "20 at once, then wait".
	RateLimit float64

	// OnResult, if set, is called once per send as results complete. It is
	// invoked from multiple goroutines; the callback must be safe to call
	// concurrently (the CLI serializes it behind a mutex).
	OnResult func(Result)

	// OnMatch, if set, is called only for results that pass the matcher/filter
	// gate, with the exact request bytes that were sent — Result carries only
	// signals, so this is how a caller recovers a matched request (e.g. to hand
	// it to Burp's Organizer). Invoked on the same serialized path as OnResult;
	// keep it cheap (append, don't do blocking I/O here).
	OnMatch func(r Result, rawRequest []byte)
}
