package http_request_smuggling

import (
	"fmt"
	"slices"
	"strings"
	"time"

	httputil "github.com/projectdiscovery/utils/http"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// Timing thresholds, in the units their names imply. See desyncSlower for what
// each one rules out.
//
// These are vars rather than consts only so the module's own tests can shrink
// them and exercise the real ScanPerHost path without multi-second sleeps.
// Nothing outside this package's tests may write to them, and the package must
// stay non-parallel (no t.Parallel) while that is true.
var (
	probeControlMultiplier = 3
	probeControlMargin     = 2 * time.Second
	timingFloor            = 5 * time.Second
	// controlSamples: how many control requests to take. The median discards a
	// single unlucky sample; one measurement is not a baseline.
	controlSamples = 3
)

// smugglingProbe defines a request smuggling test case.
//
// headers is written to the wire verbatim, in order, including duplicates and
// unusual casing - the TE.TE probe's two Transfer-Encoding headers differ only
// in case, which a map cannot express at all. body is written verbatim too, and
// in particular is NOT required to agree with the Content-Length the probe
// declares: the disagreement between the two is the entire attack primitive.
type smugglingProbe struct {
	name    string
	headers []httpmsg.HttpHeader
	body    string
	desc    string
}

// CL.TE: backend uses Transfer-Encoding, frontend uses Content-Length
// TE.CL: backend uses Content-Length, frontend uses Transfer-Encoding
var probes = []smugglingProbe{
	{
		name: "CL.TE Basic",
		headers: []httpmsg.HttpHeader{
			{Name: "Content-Length", Value: "4"},
			{Name: "Transfer-Encoding", Value: "chunked"},
		},
		body: "1\r\nZ\r\nQ\r\n\r\n",
		desc: "CL.TE desync: frontend uses Content-Length, backend uses Transfer-Encoding. The extra data after the chunked body may be treated as a separate request.",
	},
	{
		name: "TE.CL Basic",
		headers: []httpmsg.HttpHeader{
			{Name: "Content-Length", Value: "6"},
			{Name: "Transfer-Encoding", Value: "chunked"},
		},
		body: "0\r\n\r\nX",
		desc: "TE.CL desync: frontend uses Transfer-Encoding, backend uses Content-Length. Content after the terminating chunk may be treated as a separate request.",
	},
	{
		name: "TE.TE Obfuscation",
		headers: []httpmsg.HttpHeader{
			{Name: "Content-Length", Value: "4"},
			{Name: "Transfer-Encoding", Value: "chunked"},
			{Name: "Transfer-encoding", Value: "x"},
		},
		body: "1\r\nZ\r\nQ\r\n\r\n",
		desc: "TE.TE desync via header obfuscation: uses duplicate Transfer-Encoding headers with different casing to confuse parsers.",
	},
	{
		name: "Chunked Extension",
		headers: []httpmsg.HttpHeader{
			{Name: "Content-Length", Value: "4"},
			{Name: "Transfer-Encoding", Value: "chunked"},
		},
		body: "1;ext=val\r\nZ\r\n0\r\n\r\n",
		desc: "Chunked extension confusion: uses chunk extension syntax that may be parsed differently.",
	},
	{
		name: "TE Tab Obfuscation",
		headers: []httpmsg.HttpHeader{
			{Name: "Content-Length", Value: "4"},
			{Name: "Transfer-Encoding", Value: "\tchunked"},
		},
		body: "1\r\nZ\r\nQ\r\n\r\n",
		desc: "Transfer-Encoding with leading tab may bypass header parsing.",
	},
}

// controlProbe is the reference reading: a well-formed POST of the same shape as
// every probe, whose Content-Length matches its body exactly and which carries
// no Transfer-Encoding. It cannot trigger a CL/TE desync by construction, which
// is what makes it the only comparison that isolates framing.
var controlProbe = smugglingProbe{
	name:    "well-formed control",
	headers: []httpmsg.HttpHeader{{Name: "Content-Length", Value: "1"}},
	body:    "1",
}

// Module implements the HTTP Request Smuggling active scanner.
type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new HTTP Request Smuggling module.
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
			modkit.ScanScopeHost,
			modkit.AllInsertionPointTypes,
		),
		ds: dedup.LazyDiskSet("http_request_smuggling"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// IncludesBaseCanProcess returns false because this module uses a custom CanProcess
// that does not include the base URL/media/method checks.
func (m *Module) IncludesBaseCanProcess() bool { return false }

// CanProcess checks if the request is suitable for smuggling tests.
func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	if ctx == nil || ctx.Request() == nil {
		return false
	}
	if ctx.Response() == nil {
		return false
	}
	return true
}

// ScanPerHost runs smuggling probes once per unique host.
func (m *Module) ScanPerHost(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	service := ctx.Service()
	if service == nil {
		return nil, nil
	}

	host := service.Host()

	diskSet := m.ds.Get(scanCtx.DedupMgr())
	if !modkit.BeginHostProbe(scanCtx, httpClient, diskSet, host) {
		return nil, nil
	}

	// Preconditions. Each of these makes a timing reading unattributable to
	// framing, so the honest answer is to not test the host rather than to emit
	// a finding the evidence cannot support.
	if !hostIsTestable(ctx, httpClient) {
		return nil, nil
	}

	// CL.0 does not depend on the timing control below: it observes its own
	// effect on a follow-up request, so a host whose captured path rejects the
	// control POST can still have a static path that ignores Content-Length.
	results := scanCL0(ctx)

	control, ok := measureControl(ctx, httpClient)
	if !ok {
		return results, nil
	}

	for _, probe := range probes {
		probeRaw, ok := buildRequest(ctx, probe)
		if !ok {
			continue
		}

		// A transport error is usually a timeout, which is the signature the
		// class predicts: a parser left waiting for bytes the other end never
		// framed. It still has to out-run the control and survive confirmation.
		sent := sendOnce(ctx, httpClient, probeRaw)
		if sent.err == nil && sent.blocked {
			// The edge answered, not the origin's parser chain. Timing here
			// measures the edge rejecting us.
			continue
		}
		if !desyncSlower(sent.elapsed, control.median) {
			continue
		}
		if ev, ok := confirmTimingDesync(ctx, probeRaw, httpClient, control); ok {
			results = append(results, buildResult(
				ctx, probeRaw, probe, control, sent.elapsed, sent.err != nil, ev))
		}
	}

	return results, nil
}

// desyncSlower reports whether a probe is slow in a way a well-formed control of
// the same shape is not.
//
// All three conditions are required. The ratio alone fires on a fast host where
// a 40ms control and a 150ms probe differ only by scheduling noise; the absolute
// margin alone fires on any slow host; the floor keeps the claim consistent with
// a parser blocking rather than with ordinary latency.
//
// The comparison is deliberately NOT against the host's original (usually GET)
// response time. Against a CDN a cached GET returns in tens of milliseconds
// while any POST is forwarded to origin and takes seconds, so a GET baseline
// makes every POST look anomalous - on every host, for every probe.
func desyncSlower(probe, control time.Duration) bool {
	return probe > timingFloor &&
		probe > control*time.Duration(probeControlMultiplier) &&
		probe-control >= probeControlMargin
}

// controlReading is the well-formed-POST reference a probe is judged against.
type controlReading struct {
	median time.Duration
	raw    []byte
}

// sent is one completed send: how long it took, whether something in front of
// the application answered, and the response for evidence.
type sent struct {
	elapsed time.Duration
	blocked bool
	body    string
	err     error
}

// sendOnce writes raw to the wire verbatim and times the round trip.
//
// Options.RawBytes is mandatory here, not an optimization: see its documentation
// in pkg/http. A probe sent any other way is re-framed into an ordinary
// well-formed POST, which is byte-identical in framing to the control - so the
// module would be comparing a POST against the same POST and attributing the
// difference to a desync.
func sendOnce(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	raw []byte,
) sent {
	req := httpmsg.NewRequestResponseRaw(raw, ctx.Service())
	start := time.Now()
	resp, measured, err := httpClient.Execute(req, http.Options{
		RawBytes:    raw,
		NoRedirects: true,
	})

	// Execute starts its clock after the rate token and the per-host permit, so
	// vigolium's own queueing stays out of a reading that is compared against a
	// 5s floor. It reports 0 on error, where wall-clock is all there is.
	out := sent{elapsed: measured, err: err}
	if out.elapsed == 0 {
		out.elapsed = time.Since(start)
	}
	if resp != nil {
		out.blocked = isEdgeOrGateResponse(resp)
		out.body = resp.FullResponseString()
		resp.Close()
	}
	return out
}

// hostIsTestable checks the preconditions under which a timing differential
// could mean anything at all. It sends the host's own captured request once and
// reads the answer.
func hostIsTestable(ctx *httpmsg.HttpRequestResponse, httpClient *http.Requester) bool {
	// NoClustering: a cache hit is served from a reconstructed response, and
	// rebuilding one is lossy in ways the checks below depend on. The
	// preconditions have to look at a real response.
	resp, _, err := httpClient.Execute(ctx, http.Options{NoClustering: true})
	if err != nil || resp == nil || resp.Response() == nil {
		return false
	}
	defer resp.Close()

	// The host's normal answer is already an edge/CDN/WAF rejection or an auth
	// gate: requests never reach an origin frontend/backend parser chain, so
	// every probe measures the same edge processing and no reading can be
	// attributed to a desync.
	if isEdgeOrGateResponse(resp) {
		return false
	}

	// CL/TE desync is an HTTP/1.1 framing attack. Over HTTP/2 the framing is
	// carried in frames rather than headers, Transfer-Encoding is a connection
	// header the protocol forbids, and these probes are not expressible. (The
	// probes themselves always go out over HTTP/1.1 via rawhttp; what this reads
	// is whether the host's normal traffic is HTTP/1.1 at all.)
	if resp.Response().ProtoMajor != 1 {
		return false
	}

	// Smuggling is an attack on a SHARED connection: the smuggled prefix has to
	// sit in a buffer waiting for the next request to arrive on the same socket.
	// A front-end that closes the connection after every response leaves no
	// socket to poison, so there is nothing here to find regardless of what the
	// timing says.
	return !connectionWillClose(resp)
}

// measureControl sends the well-formed control several times and returns the
// median. A single sample is a coin flip on a shared host; the median of three
// discards one unlucky scheduling artifact without pretending to be statistics.
func measureControl(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
) (controlReading, bool) {
	controlRaw, ok := buildRequest(ctx, controlProbe)
	if !ok {
		return controlReading{}, false
	}

	samples := make([]time.Duration, 0, controlSamples)
	for range controlSamples {
		out := sendOnce(ctx, httpClient, controlRaw)
		// A host that cannot answer a plain, unambiguous POST cannot be called
		// desynced on the strength of a slow malformed one. A control that never
		// reached the origin is not a reference for anything either - that gap is
		// what let a fast edge 403 read as "the probe's slowness is
		// desync-specific".
		if out.err != nil || out.blocked {
			return controlReading{}, false
		}
		samples = append(samples, out.elapsed)
	}

	return controlReading{median: medianDuration(samples), raw: controlRaw}, true
}

// desyncEvidence carries the confirmation-round measurements confirmTimingDesync
// takes while validating a timing anomaly: the reconfirmed probe (which must
// still out-run the control) and the freshly re-measured control (which must
// still be fast). Preserving these lets the finding show the differential that
// distinguishes a real desync from a host that is simply slow for POST traffic,
// instead of asserting it in prose.
type desyncEvidence struct {
	reElapsed   time.Duration
	probeResp   string
	ctrlElapsed time.Duration
	ctrlResp    string
}

// confirmTimingDesync re-validates a probe that produced an initial timing
// anomaly. A single slow response is not enough on its own: it is most often
// network jitter, a transient backend stall, or general host/path latency. We
// only keep the finding when:
//
//  1. the slowness reproduces on a second send of the same probe (rules out
//     one-off jitter), and the re-send is not an edge/CDN/WAF block, and
//  2. a well-formed control POST re-measured NOW is still fast relative to the
//     probe - re-measured rather than reused, so that a host which simply got
//     slower between the control round and the probe cannot be reported as a
//     desync.
func confirmTimingDesync(
	ctx *httpmsg.HttpRequestResponse,
	probeRaw []byte,
	httpClient *http.Requester,
	control controlReading,
) (desyncEvidence, bool) {
	// 1. Reconfirm the anomaly with a fresh send of the same probe. A reproduced
	// block means the edge is rejecting us, not a desync.
	reprobe := sendOnce(ctx, httpClient, probeRaw)
	ev := desyncEvidence{reElapsed: reprobe.elapsed, probeResp: reprobe.body}
	if reprobe.err == nil && reprobe.blocked {
		return ev, false
	}
	if !desyncSlower(reprobe.elapsed, control.median) {
		return ev, false
	}

	// 2. Re-measure the control right after the probe. If the host has simply
	// become slow, this catches it; the earlier median cannot.
	ctrl := sendOnce(ctx, httpClient, control.raw)
	if ctrl.err != nil || ctrl.blocked {
		return ev, false
	}
	ev.ctrlElapsed = ctrl.elapsed
	ev.ctrlResp = ctrl.body

	// The probe must out-run the control the confirmation round just measured,
	// not only the one measured before the probes began.
	return ev, desyncSlower(reprobe.elapsed, ctrl.elapsed)
}

func medianDuration(ds []time.Duration) time.Duration {
	if len(ds) == 0 {
		return 0
	}
	sorted := slices.Clone(ds)
	slices.Sort(sorted)
	return sorted[len(sorted)/2]
}

// buildRequest renders a probe against the host's captured request: forced to
// POST, stripped of any captured framing headers, then carrying the probe's own
// header lines verbatim and in order, with its body attached as-is.
//
// It builds the message directly rather than going through SetBody, because
// SetBody recomputes Content-Length to match the body it is given. That silently
// repaired the CL/TE disagreement the probes exist to create: "Content-Length: 4"
// went out as 11 or 19, matching the body exactly, leaving a request with
// correct framing and nothing to desync.
func buildRequest(ctx *httpmsg.HttpRequestResponse, probe smugglingProbe) ([]byte, bool) {
	if ctx == nil || ctx.Request() == nil {
		return nil, false
	}
	raw, err := httpmsg.SetMethod(ctx.Request().Raw(), "POST")
	if err != nil {
		return nil, false
	}
	headers, _, _, err := httpmsg.ExtractAllHeaders(raw)
	if err != nil || len(headers) == 0 {
		return nil, false
	}

	lines := make([]string, 0, len(headers)+len(probe.headers))
	lines = append(lines, headers[0]) // request line
	for _, header := range headers[1:] {
		// The probe owns framing outright: a Content-Length or Transfer-Encoding
		// carried by the capture must not survive alongside the crafted one.
		name, _, found := strings.Cut(header, ":")
		if !found {
			continue
		}
		name = strings.TrimSpace(name)
		if strings.EqualFold(name, "Content-Length") || strings.EqualFold(name, "Transfer-Encoding") {
			continue
		}
		lines = append(lines, header)
	}
	for _, h := range probe.headers {
		lines = append(lines, h.String())
	}
	return httpmsg.BuildHttpMessage(lines, []byte(probe.body)), true
}

// buildResult constructs the finding for a confirmed timing anomaly. It carries
// the confirmation differential captured by confirmTimingDesync - the
// reconfirmed slow probe and the re-measured fast control - as
// AdditionalEvidence and Metadata, so the proof of "desync, not a generally slow
// host" travels with the finding instead of being collapsed to a one-line claim.
func buildResult(
	ctx *httpmsg.HttpRequestResponse,
	probeRaw []byte,
	probe smugglingProbe,
	control controlReading,
	elapsed time.Duration,
	timeout bool,
	ev desyncEvidence,
) *output.ResultEvent {
	nameSuffix, timingNote := "", ""
	if timeout {
		nameSuffix, timingNote = " (Timeout)", " (timeout)"
	}

	collector := modkit.NewEvidenceCollector()
	collector.Add("reconfirm probe (anomaly reproduced)", string(probeRaw), ev.probeResp)
	collector.Add("well-formed control (re-measured after the probe)", string(control.raw), ev.ctrlResp)

	return &output.ResultEvent{
		URL:                ctx.Target(),
		Matched:            ctx.Target(),
		Request:            string(probeRaw),
		Response:           ev.probeResp,
		AdditionalEvidence: collector.Entries(),
		ExtractedResults: []string{
			fmt.Sprintf("Probe: %s", probe.name),
			fmt.Sprintf("Probe: %s%s vs well-formed control: %s (median of %d)",
				elapsed, timingNote, control.median, controlSamples),
			fmt.Sprintf("Reconfirm probe: %s (anomaly reproduced)", ev.reElapsed),
			fmt.Sprintf("Control re-measured after the probe: %s", ev.ctrlElapsed),
			fmt.Sprintf("Differential: probe is %.1fx the control and %s slower",
				ratio(ev.reElapsed, ev.ctrlElapsed), ev.reElapsed-ev.ctrlElapsed),
			"Confirmation: anomaly reproduced, a well-formed control of the same shape " +
				"over the same transport stayed fast, and neither response was an edge/CDN block",
		},
		Metadata: map[string]any{
			"probe_ms":            elapsed.Milliseconds(),
			"reconfirm_ms":        ev.reElapsed.Milliseconds(),
			"control_ms":          ev.ctrlElapsed.Milliseconds(),
			"control_median_ms":   control.median.Milliseconds(),
			"control_samples":     controlSamples,
			"timeout":             timeout,
			"framing_sent_raw":    true,
			"probe_control_ratio": ratio(ev.reElapsed, ev.ctrlElapsed),
		},
		Info: output.Info{
			Name:        fmt.Sprintf("HTTP Request Smuggling: %s%s", probe.name, nameSuffix),
			Description: probe.desc,
			// Timing inference cannot by itself distinguish a desync from any
			// other cause of a stalled read, so even a confirmed differential is
			// reported as suspect/tentative. Proof requires showing the smuggled
			// prefix affecting a subsequent request on the same connection.
			Severity:   severity.Suspect,
			Confidence: severity.Tentative,
		},
	}
}

func ratio(a, b time.Duration) float64 {
	if b <= 0 {
		return 0
	}
	return float64(a) / float64(b)
}

// connectionWillClose reports whether the server signalled that it is closing
// the connection rather than keeping it alive for a subsequent request.
func connectionWillClose(resp *httputil.ResponseChain) bool {
	if resp == nil || resp.Response() == nil {
		return false
	}
	r := resp.Response()
	if r.Close {
		return true
	}
	// Substring, not equality: Connection is a comma-separated list, so a
	// "keep-alive, close" still closes. This matches infra.RQPAmplification,
	// which gates the same keep-alive precondition for cache-poisoning probes.
	return strings.Contains(strings.ToLower(r.Header.Get("Connection")), "close")
}

// isEdgeOrGateResponse reports whether the response came from something in FRONT
// of the application - a CDN/WAF rejection, or an authentication gate - rather
// than from the origin whose parser chain is under test. A timing reading taken
// against such a response measures the edge, not a desync, so it must never back
// a smuggling finding.
func isEdgeOrGateResponse(resp *httputil.ResponseChain) bool {
	if resp == nil || resp.Response() == nil {
		return false
	}
	// The shared detector first: it recognizes the vendor fingerprints and the
	// challenge-interstitial markers (Cloudflare, Incapsula, Netlify, ...) that
	// looksLikeEdgeBlockPage therefore does not repeat.
	if infra.GetBlockDetectionValidator().Validate(resp) != nil {
		return true
	}

	r := resp.Response()

	// An authentication gate answered. The request was rejected on credentials
	// before the application ever processed it, so whatever the origin's parser
	// chain does with our framing was never exercised.
	if r.StatusCode == 401 && r.Header.Get("WWW-Authenticate") != "" {
		return true
	}

	// Body-marker check for edge error pages the shared detector does not
	// recognize. The status list is broad because CDNs serve their interstitials
	// under whatever status fits - a CloudFront "AdmitOne" 404 and an Akamai 403
	// are both the edge talking - but a marker match is still required, so an
	// ordinary application 404 is unaffected.
	switch r.StatusCode {
	case 400, 401, 403, 404, 405, 429, 500, 502, 503:
		return looksLikeEdgeBlockPage(resp.BodyString())
	}
	return false
}

// looksLikeEdgeBlockPage detects CDN/WAF interstitial block pages by body
// marker. These pages are served by the edge before the origin chain is ever
// reached, so any timing measured against them is meaningless for desync.
//
// This list is deliberately local rather than shared with infra/modkit: those
// sets must be conservative, because a false "blocked" there silently deletes a
// real finding in the ~100 modules that consume them. Here the preference is the
// opposite - a reading this module cannot attribute is worthless, so it skips on
// ambiguity. Markers the shared detector already covers are not repeated.
func looksLikeEdgeBlockPage(body string) bool {
	if body == "" {
		return false
	}
	lower := strings.ToLower(body)
	markers := []string{
		"cf-error-details",                   // Cloudflare error page container
		"cloudflare ray id",                  // Cloudflare footer
		"/cdn-cgi/",                          // Cloudflare edge asset path
		"edge ip restricted",                 // Cloudflare error 1034
		"attention required",                 // Cloudflare challenge/block
		"error 1020",                         // Cloudflare access denied
		"access denied",                      // Akamai / generic WAF
		"akamaighost",                        // Akamai
		"the request could not be satisfied", // CloudFront
		"generated by cloudfront",            // CloudFront error footer
		"admitone",                           // CloudFront/S3 edge rejection cookie page
		"requested url was rejected",         // F5 BIG-IP ASM
	}
	for _, mk := range markers {
		if strings.Contains(lower, mk) {
			return true
		}
	}
	return false
}
