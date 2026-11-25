// Package parammine discovers hidden HTTP parameters: names an endpoint reads
// and acts on although no observed request ever carried them (debug=1,
// callback=, admin=). It is Arjun-style mining, built on vigolium's own
// response-comparison helpers:
//
//  1. Two baselines, each with one random benign parameter, give the
//     endpoint's stability profile: status, header-name set, normalized body
//     hash and a length/similarity signature. An endpoint whose two baselines
//     disagree is unstable and is abandoned rather than mined.
//  2. The candidate names are sent in chunks sized to the transport (a 6 KiB
//     request target for the query string, 32 KiB for a form or JSON body),
//     each name carrying its own random canary value.
//  3. A chunk whose response differs from the baseline (status, header set,
//     body via modkit.IsDifferent / modkit.HasSubstantialBodyDifference /
//     similarity) is bisected, both halves at a time, down to single names. A
//     canary echoed in the response maps straight to its name, no bisection
//     needed.
//  4. Every single-name candidate is re-sent ConfirmRounds times with fresh
//     canaries and kept only when the signal reproduces each time.
//
// The miner sends nothing itself: the caller supplies a Sender, so the scan
// phase routes through the shared requester (session, rate limit, host limiter)
// and the kit command through a requester of its own. Each endpoint is bounded
// by Config.MaxRequests, and mining stops on a burst of 403/429 or edge-block
// answers rather than keep feeding a WAF.
package parammine

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
)

// Location is where the mined names are placed in the request.
type Location string

const (
	LocationQuery Location = "query" // appended to the URL query string
	LocationForm  Location = "form"  // appended to an application/x-www-form-urlencoded body
	LocationJSON  Location = "json"  // added as top-level keys of a JSON object body
	// LocationHeader sends each name as a request header carrying its canary
	// value. Never inferred from the request: --location header asks for it.
	LocationHeader Location = "header"
	// LocationCookie sends each name as a cookie carrying its canary value,
	// merged into the request's Cookie header beside the cookies it already
	// sends (a session is never replaced). Never inferred from the request:
	// --location cookie asks for it.
	LocationCookie Location = "cookie"
)

// Signal is the observable difference that revealed a parameter.
type Signal string

const (
	SignalReflect Signal = "reflect" // the parameter's canary value was echoed back
	SignalStatus  Signal = "status"  // the status code changed
	SignalHeader  Signal = "header"  // the set of response header names changed
	SignalLength  Signal = "length"  // the body length moved past the substantial-difference bound
	SignalBody    Signal = "body"    // the body content changed at a similar length
)

// Abort reasons reported in Result.Aborted. Empty means the whole wordlist was
// tested within budget.
const (
	AbortUnstable = "unstable"        // the two baselines disagreed
	AbortBlocked  = "blocked"         // a burst of 403/429/edge-block answers
	AbortBudget   = "budget"          // Config.MaxRequests was reached
	AbortBaseline = "baseline_failed" // a baseline request got no HTTP answer
	AbortErrors   = "errors"          // consecutive transport errors
	AbortCanceled = "canceled"        // the context ended
)

// Defaults for the zero Config.
const (
	DefaultMaxRequests      = 60
	DefaultMaxQueryBytes    = 6 << 10
	DefaultMaxBodyBytes     = 32 << 10
	DefaultConfirmRounds    = 2
	DefaultBlockBurst       = 3
	DefaultMaxNamesPerChunk = 256
	// DefaultMaxHeaderBytes caps the bytes a header chunk adds, and
	// DefaultMaxHeadersPerChunk the header fields a request carries in all.
	// Servers bound both (nginx answers 400 past an 8 KiB header buffer, Apache
	// past LimitRequestFields 100 fields), and a 400 from too many headers
	// would read as a signal.
	DefaultMaxHeaderBytes     = 4 << 10
	DefaultMaxHeadersPerChunk = 60
	// DefaultMaxCookieHeaderBytes caps a mining request's whole Cookie header,
	// the cookies the request already sends included: past an 8 KiB header
	// line nginx answers 400, which would read as a signal. A cookie chunk
	// adds at most MaxHeaderBytes, and only the room this leaves.
	DefaultMaxCookieHeaderBytes = 6 << 10

	// maxErrorRun is how many consecutive transport errors end the endpoint.
	maxErrorRun = 3
	// canaryLen is the length of each random parameter value.
	canaryLen = 9
)

// Sender sends one request and returns its response. Redirects must not be
// followed: a hidden parameter that triggers a redirect is a status signal.
type Sender func(ctx context.Context, rr *httpmsg.HttpRequestResponse) (*httpmsg.HttpResponse, error)

// Config bounds one endpoint's mining. Zero fields take the defaults above.
type Config struct {
	// MaxRequests is the per-endpoint request budget, baselines and
	// confirmations included.
	MaxRequests int
	// MaxQueryBytes caps the request target (path plus query string) of a
	// query-location chunk.
	MaxQueryBytes int
	// MaxBodyBytes caps the body of a form or JSON chunk.
	MaxBodyBytes int
	// MaxHeaderBytes caps what a header-location chunk adds to the request.
	MaxHeaderBytes int
	// MaxNamesPerChunk caps the names in one chunk regardless of size; many
	// stacks drop parameters past a count (PHP max_input_vars).
	MaxNamesPerChunk int
	// ConfirmRounds is how many fresh-canary re-sends a candidate must survive.
	ConfirmRounds int
	// BlockBurst is how many consecutive 403/429/edge-block answers stop the
	// endpoint.
	BlockBurst int
	// Location forces where names go. Empty picks one from the request: the
	// query string for bodiless methods, the body's own encoding otherwise.
	Location Location
}

func (c Config) withDefaults() Config {
	if c.MaxRequests <= 0 {
		c.MaxRequests = DefaultMaxRequests
	}
	if c.MaxQueryBytes <= 0 {
		c.MaxQueryBytes = DefaultMaxQueryBytes
	}
	if c.MaxBodyBytes <= 0 {
		c.MaxBodyBytes = DefaultMaxBodyBytes
	}
	if c.MaxHeaderBytes <= 0 {
		c.MaxHeaderBytes = DefaultMaxHeaderBytes
	}
	if c.MaxNamesPerChunk <= 0 {
		c.MaxNamesPerChunk = DefaultMaxNamesPerChunk
	}
	if c.ConfirmRounds <= 0 {
		c.ConfirmRounds = DefaultConfirmRounds
	}
	if c.BlockBurst <= 0 {
		c.BlockBurst = DefaultBlockBurst
	}
	return c
}

// Hit is one confirmed hidden parameter.
type Hit struct {
	Name     string   `json:"name"`
	Signal   Signal   `json:"signal"`
	Location Location `json:"location"`
	// Detail says what changed, e.g. "status 200 -> 302".
	Detail string `json:"detail,omitempty"`
	// Exchange is the last confirming request (carrying only this parameter
	// on top of the original request) and its response.
	Exchange *httpmsg.HttpRequestResponse `json:"-"`
}

// Result is one endpoint's mining outcome.
type Result struct {
	URL      string   `json:"url"`
	Method   string   `json:"method"`
	Location Location `json:"location"`
	Hits     []Hit    `json:"params"`
	// Unconfirmed are names the scan isolated but mining could not confirm
	// because it was cut short (block burst, transport errors, cancellation,
	// budget) — leads, not proven parameters. Their Exchange is the probe that
	// singled them out.
	Unconfirmed []Hit `json:"unconfirmed,omitempty"`
	// Tested is how many candidate names were sent at least once.
	Tested int `json:"names_tested"`
	// Requests is how many requests mining sent for this endpoint.
	Requests int `json:"requests"`
	// Aborted is why mining stopped early (Abort*), empty when it finished.
	Aborted string `json:"aborted,omitempty"`
}

// ErrNoRequest is returned for a nil base request.
var ErrNoRequest = errors.New("parammine: no base request")

// Mine tests words against the endpoint base describes and returns the
// parameters it confirmed. words is used in order (put the likeliest first);
// names the base request already carries are skipped. Mine returns an error
// only for unusable input; every runtime failure is a Result.Aborted reason.
func Mine(ctx context.Context, base *httpmsg.HttpRequestResponse, words []string, send Sender, cfg Config) (res Result, err error) {
	if base == nil || base.Request() == nil {
		return Result{}, ErrNoRequest
	}
	if send == nil {
		return Result{}, errors.New("parammine: no sender")
	}
	cfg = cfg.withDefaults()
	b, err := newBuilder(base, cfg.Location)
	if err != nil {
		return Result{}, err
	}
	m := &miner{cfg: cfg, send: send, b: b}
	res = Result{URL: base.Target(), Method: base.Request().Method(), Location: b.loc}
	defer func() { res.Requests = m.requests }()

	names := b.filterExisting(words)
	// The scan stops short of the budget so the candidates it isolates can
	// still be confirmed: a budget spent entirely on bisection used to discard
	// every candidate.
	m.limit = cfg.MaxRequests - confirmReserve(cfg)
	if !m.baseline(ctx) {
		res.Aborted = m.aborted
		return res, nil
	}

	cands := m.scan(ctx, names, &res.Tested)
	scanAbort := m.aborted
	switch scanAbort {
	case "", AbortBudget:
		// Out of scan budget is no reason not to confirm: the reserve is for it.
		m.aborted = ""
		m.limit = cfg.MaxRequests
		res.Hits, res.Unconfirmed = m.confirm(ctx, cands)
	default:
		// Blocked, erroring or canceled: confirming would keep feeding the
		// block. Report what the scan isolated as unconfirmed leads.
		for _, c := range cands {
			res.Unconfirmed = append(res.Unconfirmed, m.unconfirmed(c, scanAbort))
		}
	}
	res.Aborted = m.aborted
	if res.Aborted == "" {
		res.Aborted = scanAbort
	}
	return res, nil
}

// confirmReserve is the part of the budget the scan leaves for confirmation:
// ConfirmRounds re-sends for up to three candidates, at most a third of the
// budget.
func confirmReserve(cfg Config) int {
	return min(cfg.ConfirmRounds*3, cfg.MaxRequests/3)
}

// pair is one parameter as sent: a name and the canary value it carried.
type pair struct{ name, value string }

// candidate is a name a chunk or bisection singled out, awaiting confirmation.
type candidate struct {
	name   string
	signal Signal
	detail string
	// src is the probe that singled the name out (may carry other names).
	src *probe
}

type miner struct {
	cfg  Config
	send Sender
	b    *builder
	prof *profile

	requests int
	// limit is the request ceiling of the current stage: the scan stops short
	// of MaxRequests to leave the confirmation reserve.
	limit    int
	blockRun int
	errRun   int
	aborted  string
}

// probe is one sent request and what it showed.
type probe struct {
	pairs     []pair
	req       *httpmsg.HttpRequestResponse
	resp      *httpmsg.HttpResponse
	err       error
	reflected map[string]bool // names whose canary came back
	// edgeBlocked marks a WAF/CDN answer. It is bisected like any other
	// difference (a WAF rule keyed on one name is isolated, and a block burst
	// stops the endpoint), but never confirmed as a parameter.
	edgeBlocked bool
}

// send builds and sends one request with pairs, accounting the budget and the
// abort conditions. ok is false when mining must stop (budget, block burst,
// error run, cancellation); p is still returned when a request went out.
func (m *miner) sendPairs(ctx context.Context, pairs []pair) (p *probe, ok bool) {
	if m.aborted != "" {
		return nil, false
	}
	if ctx.Err() != nil {
		m.aborted = AbortCanceled
		return nil, false
	}
	limit := m.limit
	if limit <= 0 || limit > m.cfg.MaxRequests {
		limit = m.cfg.MaxRequests
	}
	if m.requests >= limit {
		m.aborted = AbortBudget
		return nil, false
	}
	req, err := m.b.build(pairs)
	if err != nil {
		// A build failure is the miner's own bug, not the endpoint's; stop.
		m.aborted = AbortErrors
		return nil, false
	}
	m.requests++
	resp, err := m.send(ctx, req)
	p = &probe{pairs: pairs, req: req, resp: resp, err: err}
	if err != nil || resp == nil {
		if ctx.Err() != nil {
			m.aborted = AbortCanceled
			return p, false
		}
		m.errRun++
		if m.errRun >= maxErrorRun {
			m.aborted = AbortErrors
			return p, false
		}
		return p, true
	}
	m.errRun = 0
	p.edgeBlocked = modkit.IsEdgeBlockedResponse(resp)
	if m.blockLike(p) {
		m.blockRun++
		if m.blockRun >= m.cfg.BlockBurst {
			m.aborted = AbortBlocked
			return p, false
		}
	} else {
		m.blockRun = 0
	}
	p.reflected = reflectedNames(resp, pairs)
	return p, true
}

// blockLike reports an answer that counts toward the block burst: an edge
// block, a 429, or a 403 the baseline did not give. A single 403 can be a real
// hidden-parameter signal (admin=1 → forbidden); a run of them across halves
// that cannot all hold the culprit is a WAF.
func (m *miner) blockLike(p *probe) bool {
	if p.edgeBlocked {
		return true
	}
	switch p.resp.StatusCode() {
	case 429:
		return true
	case 403:
		return m.prof == nil || m.prof.status != 403
	}
	return false
}

// baseline sends the two random-parameter baselines and builds the profile.
func (m *miner) baseline(ctx context.Context) bool {
	var shots [2]*probe
	for i := range shots {
		p, ok := m.sendPairs(ctx, []pair{{name: randomToken(), value: randomToken()}})
		if !ok {
			return false
		}
		if p.err != nil || p.resp == nil {
			m.aborted = AbortBaseline
			return false
		}
		if p.edgeBlocked {
			m.aborted = AbortBlocked
			return false
		}
		shots[i] = p
	}
	prof, stable := newProfile(shots[0], shots[1])
	if !stable {
		m.aborted = AbortUnstable
		return false
	}
	m.prof = prof
	return true
}

// scan sends every chunk and bisects the ones that differ. tested counts the
// names that went out.
func (m *miner) scan(ctx context.Context, names []string, tested *int) []candidate {
	var cands []candidate
	seen := make(map[string]bool)
	add := func(c candidate) {
		if !seen[c.name] {
			seen[c.name] = true
			cands = append(cands, c)
		}
	}
	for _, chunk := range m.b.chunk(names, m.cfg) {
		p, ok := m.sendPairs(ctx, withCanaries(chunk))
		if p != nil && p.resp != nil {
			*tested += len(chunk)
		}
		if !ok {
			break
		}
		m.evaluate(ctx, p, chunk, add)
		if m.aborted != "" {
			break
		}
	}
	return cands
}

// evaluate turns one probe over names into candidates: reflected canaries
// directly, any other difference by bisecting the remaining names.
func (m *miner) evaluate(ctx context.Context, p *probe, names []string, add func(candidate)) {
	if p == nil || p.resp == nil {
		return
	}
	rest := m.splitReflected(p, names, add)
	sig, detail, diff := m.prof.differs(p)
	if !diff || len(rest) == 0 {
		return
	}
	if len(rest) < len(names) {
		// The reflected names may be what changed the page; re-test the others
		// alone before spending a bisection on them.
		q, ok := m.sendPairs(ctx, withCanaries(rest))
		if !ok || q == nil || q.resp == nil {
			return
		}
		if sig, detail, diff = m.prof.differs(q); !diff {
			return
		}
		p = q
	}
	m.bisect(ctx, rest, sig, detail, p, add)
}

// splitReflected adds every name whose canary p reflected as a reflect
// candidate and returns the others (names itself when reflection is unusable
// or nothing reflected).
func (m *miner) splitReflected(p *probe, names []string, add func(candidate)) []string {
	if !m.prof.reflectUsable || len(p.reflected) == 0 {
		return names
	}
	var rest []string
	for _, n := range names {
		if p.reflected[n] {
			add(candidate{name: n, signal: SignalReflect, detail: "canary value reflected in the response", src: p})
		} else {
			rest = append(rest, n)
		}
	}
	return rest
}

// bisect narrows a group of names that differs as a whole down to the single
// names responsible. Both halves are sent before either is recursed into, so a
// lone 403 culprit alternates with a clean half instead of building a block
// burst along one branch.
func (m *miner) bisect(ctx context.Context, names []string, sig Signal, detail string, src *probe, add func(candidate)) {
	if len(names) == 1 {
		add(candidate{name: names[0], signal: sig, detail: detail, src: src})
		return
	}
	mid := len(names) / 2
	halves := [2][]string{names[:mid], names[mid:]}
	var probes [2]*probe
	for i, h := range halves {
		p, ok := m.sendPairs(ctx, withCanaries(h))
		if !ok {
			return
		}
		probes[i] = p
	}
	for i, h := range halves {
		p := probes[i]
		if p == nil || p.resp == nil {
			continue
		}
		rest := m.splitReflected(p, h, add)
		s, d, diff := m.prof.differs(p)
		if diff && len(rest) > 0 {
			m.bisect(ctx, rest, s, d, p, add)
		}
		if m.aborted != "" {
			return
		}
	}
}

// confirm re-sends each candidate alone ConfirmRounds times with fresh
// canaries and keeps the ones whose signal reproduced every time. A candidate
// whose re-send was blocked, errored or never went out (mining cut short) is
// returned as unconfirmed rather than dropped; one that answered cleanly
// without the signal is dropped.
func (m *miner) confirm(ctx context.Context, cands []candidate) (hits, unconfirmed []Hit) {
	for i, c := range cands {
		if m.aborted != "" {
			for _, rest := range cands[i:] {
				unconfirmed = append(unconfirmed, m.unconfirmed(rest, m.aborted))
			}
			return hits, unconfirmed
		}
		var last *probe
		verdict := "confirmed"
		for range m.cfg.ConfirmRounds {
			p, ok := m.sendPairs(ctx, []pair{{name: c.name, value: randomToken()}})
			if !ok || p == nil || p.resp == nil || p.edgeBlocked || m.blockLike(p) {
				verdict = "cut"
				break
			}
			if !m.reproduces(c, p) {
				verdict = "refuted"
				break
			}
			last = p
		}
		switch {
		case verdict == "confirmed" && last != nil:
			hits = append(hits, Hit{
				Name:     c.name,
				Signal:   c.signal,
				Location: m.b.loc,
				Detail:   c.detail,
				Exchange: httpmsg.NewHttpRequestResponse(last.req.Request(), last.resp),
			})
		case verdict == "cut":
			reason := m.aborted
			if reason == "" {
				reason = AbortBlocked
			}
			unconfirmed = append(unconfirmed, m.unconfirmed(c, reason))
		}
	}
	return hits, unconfirmed
}

// unconfirmed reports a candidate mining could not confirm, with why.
func (m *miner) unconfirmed(c candidate, reason string) Hit {
	h := Hit{
		Name:     c.name,
		Signal:   c.signal,
		Location: m.b.loc,
		Detail:   c.detail + " (unconfirmed: " + reason + ")",
	}
	if c.src != nil && c.src.req != nil && c.src.resp != nil {
		h.Exchange = httpmsg.NewHttpRequestResponse(c.src.req.Request(), c.src.resp)
	}
	return h
}

// reproduces reports whether a single-name re-send shows the candidate's
// signal again: its canary echoed for a reflection, any non-reflection
// difference otherwise.
func (m *miner) reproduces(c candidate, p *probe) bool {
	if c.signal == SignalReflect {
		return p.reflected[c.name]
	}
	_, _, diff := m.prof.differs(p)
	return diff
}

// withCanaries pairs each name with a fresh random value.
func withCanaries(names []string) []pair {
	out := make([]pair, len(names))
	for i, n := range names {
		out[i] = pair{name: n, value: randomToken()}
	}
	return out
}

const tokenAlphabet = "abcdefghijklmnopqrstuvwxyz0123456789"

// randomToken is a canary or a throwaway baseline name: a letter followed by
// lowercase alphanumerics, long enough never to occur in a page by chance.
func randomToken() string {
	b := make([]byte, canaryLen)
	for i := range b {
		alpha := tokenAlphabet
		if i == 0 {
			alpha = tokenAlphabet[:26]
		}
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(alpha))))
		if err != nil {
			panic(fmt.Sprintf("parammine: crypto/rand failed: %v", err))
		}
		b[i] = alpha[n.Int64()]
	}
	return string(b)
}
