package redos_probe

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
)

const (
	// baselineSamples model the parameter's normal latency (with a long
	// matching control value) before any backtracking input is sent.
	baselineSamples = 4
	// timeStdevCoeff scales the baseline jitter into the delay floor.
	timeStdevCoeff = 5
	// defaultMinFloor is the least delay a backtracking input must add over
	// its same-length control before it is believed.
	defaultMinFloor = 1500 * time.Millisecond
	// maxFloor skips targets too jittery to time reliably.
	maxFloor = 6 * time.Second
	// confirmRounds independent rounds must all show super-linear growth.
	confirmRounds = 2
	// growthMargin: the high probe's extra delay over the low probe must be at
	// least growthMargin× what linear growth in the input length would add.
	growthMargin = 2
	// unboundedOvershoot disables infra.ScaledDelayConfirmed's overshoot guard:
	// catastrophic backtracking has no requested ceiling (it is bounded only by
	// the request timeout), so an overshoot is the expected signal, not a stall.
	unboundedOvershoot = 1 << 20
)

// lengths are the "aaaa…!" sizes tried in order. Escalation stops at the first
// length whose delay clears the floor; the length before it is the low probe.
// Each step doubles, so the length ratio between low and high is always 2.
var lengths = []int{16, 32, 64}

// fallbackLow is the low probe when the first length already clears the floor.
const fallbackLow = 8

// patternTokens are parameter-name tokens naming a value that is plausibly
// regex-validated (or a user-supplied pattern), matched as whole tokens.
var patternTokens = map[string]bool{
	"email": true, "mail": true, "url": true, "uri": true, "link": true,
	"website": true, "homepage": true, "regex": true, "regexp": true,
	"pattern": true, "search": true, "query": true, "q": true,
}

var emailValueRe = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)

// patternParamTypes are the field-carrying insertion points worth timing.
var patternParamTypes = modkit.NewInsertionPointTypeSet(
	httpmsg.INS_PARAM_URL,
	httpmsg.INS_PARAM_BODY,
	httpmsg.INS_PARAM_JSON,
	httpmsg.INS_PARAM_XML,
	httpmsg.INS_PARAM_MULTIPART_ATTR,
)

// Module implements the ReDoS probe active scanner.
type Module struct {
	modkit.BaseActiveModule
	rhm dedup.Lazy[dedup.RequestHashManager]
	// minFloor is defaultMinFloor; tests lower it to keep runs short.
	minFloor time.Duration
}

// New creates a new ReDoS probe module.
func New() *Module {
	m := &Module{
		BaseActiveModule: modkit.NewBaseActiveModule(
			ModuleID,
			ModuleName,
			ModuleDesc,
			ModuleShort,
			ModuleConfirmation,
			ModuleSeverity,
			ModuleConfidence,
			modkit.ScanScopeInsertionPoint,
			patternParamTypes,
		),
		rhm:      dedup.LazyDefaultRHM("redos_probe"),
		minFloor: defaultMinFloor,
	}
	m.ModuleTags = ModuleTags
	return m
}

// attack is the backtracking input of length n: a run the pattern's nested
// quantifier can split many ways, then a character that forces it to fail.
func attack(n int) string { return strings.Repeat("a", n) + "!" }

// control is a same-length value that matches the run without failing, so
// linear per-byte cost cancels out of the attack's added delay.
func control(n int) string { return strings.Repeat("a", n+1) }

// LooksLikePatternParam reports whether a parameter is worth a ReDoS probe:
// its name names a validated or pattern-like value, or its value is an email
// address or absolute URL.
func LooksLikePatternParam(name, value string) bool {
	for _, tok := range infra.ParamNameTokens(name) {
		if patternTokens[tok] {
			return true
		}
	}
	v := strings.TrimSpace(value)
	return emailValueRe.MatchString(v) || strings.HasPrefix(v, "http://") || strings.HasPrefix(v, "https://")
}

// ScanPerInsertionPoint times growing backtracking inputs in one parameter.
func (m *Module) ScanPerInsertionPoint(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	if !patternParamTypes.Contains(ip.Type()) || !LooksLikePatternParam(ip.Name(), ip.BaseValue()) {
		return nil, nil
	}
	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}
	if !infra.IsValidForInjectionVulns(urlx, ctx) {
		return nil, nil
	}
	if rhm := m.rhm.Get(scanCtx.DedupMgr()); rhm != nil {
		if !rhm.ShouldCheckInsertionPoint(urlx, ctx.Request(), ip.Name(), ip.BaseValue(), fmt.Sprintf("%d", ip.Type())) {
			return nil, nil
		}
	}

	p := prober{m: m, ctx: ctx, ip: ip, client: httpClient}
	res, err := p.run()
	if err != nil || res == nil {
		return nil, nil
	}
	res.URL = urlx.String()
	res.Matched = urlx.String()
	return []*output.ResultEvent{res}, nil
}

// prober carries one insertion point's timing session.
type prober struct {
	m      *Module
	ctx    *httpmsg.HttpRequestResponse
	ip     httpmsg.InsertionPoint
	client *http.Requester
}

// round is one measured (control, low, high) triple.
type round struct {
	control, low, high time.Duration
}

func (p *prober) run() (*output.ResultEvent, error) {
	floor, err := p.floor()
	if err != nil || floor > maxFloor {
		return nil, err
	}

	// Escalate: the first length whose added delay clears the floor is the
	// high probe. Stopping there keeps the longest (most damaging) input
	// unsent whenever a shorter one already proves the slowdown.
	lowLen, highLen := 0, 0
	for i, n := range lengths {
		c, err := p.timed(control(n), false)
		if err != nil {
			return nil, err
		}
		a, err := p.timed(attack(n), true)
		if err != nil {
			return nil, err
		}
		if a.elapsed-c.elapsed >= floor {
			highLen = n
			lowLen = fallbackLow
			if i > 0 {
				lowLen = lengths[i-1]
			}
			break
		}
	}
	if highLen == 0 {
		return nil, nil
	}

	var rounds []round
	var proof timed
	for r := 0; r < confirmRounds; r++ {
		c, err := p.timed(control(highLen), false)
		if err != nil {
			return nil, err
		}
		low, err := p.timed(attack(lowLen), true)
		if err != nil {
			return nil, err
		}
		high, err := p.timed(attack(highLen), true)
		if err != nil {
			return nil, err
		}
		if !superLinear(c.elapsed, low.elapsed, high.elapsed, highLen/lowLen, floor) {
			return nil, nil
		}
		rounds = append(rounds, round{c.elapsed, low.elapsed, high.elapsed})
		proof = high
	}
	return p.result(rounds, proof, lowLen, highLen, floor), nil
}

// floor derives the delay a backtracking input must add over its control:
// max(minFloor, timeStdevCoeff × baseline stdev).
func (p *prober) floor() (time.Duration, error) {
	samples := make([]time.Duration, 0, baselineSamples)
	for i := 0; i < baselineSamples; i++ {
		t, err := p.timed(control(lengths[len(lengths)-1]), false)
		if err != nil {
			return 0, err
		}
		samples = append(samples, t.elapsed)
	}
	_, stdev := infra.MeanStdev(samples)
	floor := time.Duration(timeStdevCoeff) * stdev
	if floor < p.m.minFloor {
		floor = p.m.minFloor
	}
	return floor, nil
}

// superLinear is the ReDoS verdict on one round, expressed through the shared
// infra.ScaledDelayConfirmed: there is no requested sleep, so the "wanted"
// high delay is derived from the growth model instead. With the input length
// ratio r, linear matching cost would make the high probe add (r-1)× the low
// probe's delay on top of it; the high probe must add at least growthMargin×
// that (and at least the floor) beyond the low probe. A fixed stall triggered
// by the trailing "!" (a WAF, an error page) adds the same delay at both
// lengths and fails; so does linear growth.
func superLinear(controlD, lowD, highD time.Duration, ratio int, floor time.Duration) bool {
	lowDelta := lowD - controlD
	if lowDelta < 0 {
		lowDelta = 0
	}
	want := lowDelta * time.Duration(growthMargin*(ratio-1))
	if want < floor {
		want = floor
	}
	// lowWant 0 credits the low probe with nothing; scaleDenom 1 then requires
	// highDelta >= want and highDelta - lowDelta >= want.
	return infra.ScaledDelayConfirmed(controlD, controlD+lowDelta, highD, 0, want, 1, unboundedOvershoot)
}

// timed is one measured probe, with the raw exchange when captured.
type timed struct {
	elapsed  time.Duration
	request  string
	response string
}

// timed sends value through the insertion point and measures wall-clock
// latency. NoClustering forces identical probes to really re-execute. A
// backtracking (attack) probe that errors after waiting still yields its
// elapsed time: a request timeout is the expected outcome of catastrophic
// backtracking. A failing control, or an unresponsive host, aborts.
func (p *prober) timed(value string, isAttack bool) (timed, error) {
	raw := p.ip.BuildRequest([]byte(value))
	req := httpmsg.NewRequestResponseRaw(raw, p.ctx.Service())
	// SendTimed (MISS-14): requester-measured latency (also on a timeout).
	resp, elapsed, err := modkit.SendTimed(p.client, req, http.Options{})
	if err != nil {
		if !isAttack || errors.Is(err, hosterrors.ErrUnresponsiveHost) {
			return timed{}, err
		}
		return timed{elapsed: elapsed, request: string(raw)}, nil
	}
	t := timed{elapsed: elapsed}
	if isAttack {
		t.request = string(raw)
		t.response = resp.FullResponseString()
	}
	resp.Close()
	return t, nil
}

func (p *prober) result(rounds []round, proof timed, lowLen, highLen int, floor time.Duration) *output.ResultEvent {
	extracted := []string{attack(highLen), attack(lowLen), control(highLen)}
	for i, r := range rounds {
		extracted = append(extracted, fmt.Sprintf(
			"Round %d: control(%d) %dms, attack(%d) %dms, attack(%d) %dms",
			i+1, highLen, r.control.Milliseconds(), lowLen, r.low.Milliseconds(), highLen, r.high.Milliseconds()))
	}
	last := rounds[len(rounds)-1]
	ev := modkit.NewEvidenceCollector()
	ev.Add("baseline (unmodified request)", modkit.CtxRequestRaw(p.ctx), modkit.CtxResponseRaw(p.ctx))

	return &output.ResultEvent{
		Request:            proof.request,
		Response:           proof.response,
		FuzzingParameter:   p.ip.Name(),
		ExtractedResults:   extracted,
		AdditionalEvidence: ev.Entries(),
		MatcherStatus:      true,
		Info: output.Info{
			Name: ModuleName,
			Description: fmt.Sprintf(
				"Possible ReDoS in parameter %q: a backtracking input with a %d-character run added %dms over a "+
					"matching control of the same length, while a %d-character run added %dms, growth faster than the "+
					"input length, in %d independent rounds. Timing-only and network-sensitive: verify the pattern in code.",
				p.ip.Name(), highLen, (last.high - last.control).Milliseconds(),
				lowLen, max(last.low-last.control, 0).Milliseconds(), len(rounds)),
			Severity:   ModuleSeverity,
			Confidence: ModuleConfidence,
		},
		Metadata: map[string]any{
			"floor_ms":            floor.Milliseconds(),
			"confirmation_rounds": len(rounds),
			"low_run_length":      lowLen,
			"high_run_length":     highLen,
		},
	}
}
