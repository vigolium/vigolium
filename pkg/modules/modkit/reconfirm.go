package modkit

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"

	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra"
	"github.com/vigolium/vigolium/pkg/modules/shared/authzutil"
)

// This file centralizes the response-comparison machinery used to re-confirm a
// candidate finding before it is reported. It was extracted from the
// boolean-blind SQLi module's page-comparison heuristics (which mirror sqlmap's
// quick_ratio approach) so every module — and the executor's safety net — can
// reuse one battle-tested differential instead of re-implementing ad-hoc
// "response looks different" checks that produce false positives.

// Ratio thresholds for textual similarity comparison, mirroring sqlmap's
// page-comparison heuristics (UPPER_RATIO_BOUND / LOWER_RATIO_BOUND /
// DIFF_TOLERANCE): two responses whose normalized token similarity is at or
// above UpperRatioBound are treated as "the same page", below LowerRatioBound as
// "completely different", and two responses are only a differential signal when
// their similarities to a reference diverge by at least RatioDiffTolerance.
const (
	UpperRatioBound    = 0.95
	LowerRatioBound    = 0.05
	RatioDiffTolerance = 0.05

	// A "substantial" body difference is both an absolute (bytes) and a
	// relative (fraction) gap, so marginal or dynamic-noise differences are not
	// treated as meaningful.
	SubstantialBodyDeltaBytes = 100
	SubstantialBodyDeltaRatio = 0.20

	// ratioBodyScanLimit bounds how much of a response body the similarity /
	// normalization helpers tokenize. Page-identity and introduced-content
	// signals live in the head of a document; regex-scanning megabytes of a
	// minified bundle or data blob past this adds cost (and noise), not signal.
	// Mirrors the body-scan cap that block detection already applies. The
	// fast pre-filters (full-body hash + length) are unaffected — only the
	// token multiset is built from the capped head.
	ratioBodyScanLimit = 256 << 10 // 256 KiB
)

// capForRatio truncates s to at most ratioBodyScanLimit bytes for tokenization.
// Slicing on a byte boundary may split a trailing multibyte rune, which only
// produces a token boundary (harmless for the alnum tokenizer).
func capForRatio(s string) string {
	if len(s) > ratioBodyScanLimit {
		return s[:ratioBodyScanLimit]
	}
	return s
}

var (
	// reHexLong collapses long hex runs (session ids, hashes, ETags).
	reHexLong = regexp.MustCompile(`[0-9a-fA-F]{12,}`)
	// reDigits collapses long digit runs (timestamps, counters, epoch ms).
	reDigits = regexp.MustCompile(`[0-9]{4,}`)
	// reNonWord splits normalized text into alphanumeric tokens.
	reNonWord = regexp.MustCompile(`[^a-z0-9]+`)
)

// ResponseSignature captures key response attributes for comparison.
//
// In addition to the status/length/hash triple (used for fast pre-filters), it
// carries a token-count multiset derived from a normalized copy of the body.
// The multiset powers a difflib-style quick_ratio similarity that survives
// dynamic content (CSRF tokens, timestamps, reflected payloads) which a
// byte/hash comparison breaks on.
type ResponseSignature struct {
	StatusCode  int
	BodyLength  int
	BodyHash    [32]byte
	tokenCounts map[string]int
	tokenTotal  int
}

// newRatioSignature builds a ResponseSignature for QuickRatio-only comparison.
// Unlike NewResponseSignature it skips the body SHA-256 (and the full-body []byte
// copy it requires): QuickRatio/BodiesSimilar use only the token multiset, never
// BodyHash, so the hash is pure waste on the similarity path.
func newRatioSignature(body string) ResponseSignature {
	counts, total := Tokenize(NormalizeForRatio(body, ""))
	return ResponseSignature{
		BodyLength:  len(body),
		tokenCounts: counts,
		tokenTotal:  total,
	}
}

// observedPageSignature returns the memoized ratio signature for resp's body. The
// observed baseline is constant across a path-probing module's whole probe loop,
// so caching it on the response collapses ~N re-tokenizations (one per probe) into
// one. Returns the zero signature for a nil response.
func observedPageSignature(resp *httpmsg.HttpResponse) ResponseSignature {
	if resp == nil {
		return ResponseSignature{}
	}
	return resp.RatioSignature(ratioSignatureCompute).(ResponseSignature)
}

// ratioSignatureCompute is a captureless adapter passed to HttpResponse.RatioSignature
// (captureless so it is a static func value, not a per-call closure allocation).
func ratioSignatureCompute(body string) any { return newRatioSignature(body) }

// NewResponseSignature creates a signature from response attributes. reflect is
// the value injected into the request (payload or base value); its occurrences
// are stripped before tokenization so reflected input does not skew similarity.
// Pass "" for reflect when the injected value is unknown (e.g. the executor
// safety net) — the comparison stays correct, just slightly less sensitive.
func NewResponseSignature(statusCode int, body, reflect string) ResponseSignature {
	counts, total := Tokenize(NormalizeForRatio(body, reflect))
	return ResponseSignature{
		StatusCode:  statusCode,
		BodyLength:  len(body),
		BodyHash:    sha256.Sum256([]byte(body)),
		tokenCounts: counts,
		tokenTotal:  total,
	}
}

// NormalizeForRatio lowercases the body, removes reflected input, and collapses
// dynamic-looking runs (long hex/digit sequences) so they don't add noise to
// the token multiset.
func NormalizeForRatio(body, reflect string) string {
	s := strings.ToLower(capForRatio(body))
	if len(reflect) >= 3 {
		s = strings.ReplaceAll(s, strings.ToLower(reflect), " ")
	}
	s = reHexLong.ReplaceAllString(s, " ")
	s = reDigits.ReplaceAllString(s, " ")
	return s
}

// NormalizedBodyHash returns a stable hex SHA-256 over a response body that has
// been normalized for dedup: lowercased, with each reflect value (e.g. the
// request URL and path that an error/echo page mirrors back into the body) and
// dynamic-looking runs (long hex/digit sequences — timestamps, ids, hashes)
// collapsed to a space. Two bodies that differ ONLY by the reflected request
// target or per-request dynamic tokens therefore hash identically, so the single
// byte differential an echoed URL introduces no longer defeats record dedup
// (the classic "404/400 page mirrors the requested URI" case where every probed
// path yields a distinct response_hash + content_length).
//
// An empty/whitespace-only body yields "" — callers skip those: they carry no
// signal and are already collapsed by exact response-hash dedup.
func NormalizedBodyHash(body string, reflects ...string) string {
	if strings.TrimSpace(body) == "" {
		return ""
	}
	s := strings.ToLower(body)
	for _, ref := range reflects {
		if len(ref) >= 3 {
			s = strings.ReplaceAll(s, strings.ToLower(ref), " ")
		}
	}
	s = reHexLong.ReplaceAllString(s, " ")
	s = reDigits.ReplaceAllString(s, " ")
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// Tokenize splits normalized text into a token-count multiset and total count.
func Tokenize(normalized string) (map[string]int, int) {
	counts := make(map[string]int)
	total := 0
	for _, tok := range reNonWord.Split(normalized, -1) {
		if tok == "" {
			continue
		}
		counts[tok]++
		total++
	}
	return counts, total
}

// QuickRatio returns a 0..1 textual similarity between two responses, following
// difflib.SequenceMatcher.quick_ratio: 2*M / (Ta+Tb) where M is the number of
// matching tokens (sum of per-token min counts) and Ta/Tb the token totals.
// Order-independent and cheap. Two empty bodies are treated as identical.
func QuickRatio(a, b ResponseSignature) float64 {
	if a.tokenTotal == 0 && b.tokenTotal == 0 {
		return 1.0
	}
	if a.tokenTotal == 0 || b.tokenTotal == 0 {
		return 0.0
	}
	// Iterate the smaller map for fewer lookups.
	small, large := a.tokenCounts, b.tokenCounts
	if len(small) > len(large) {
		small, large = large, small
	}
	matched := 0
	for tok, sc := range small {
		if lc, ok := large[tok]; ok {
			if sc < lc {
				matched += sc
			} else {
				matched += lc
			}
		}
	}
	return 2.0 * float64(matched) / float64(a.tokenTotal+b.tokenTotal)
}

// RatioSimilar reports whether two responses are effectively the same page by
// textual similarity. Used to confirm a response is stable across retries even
// when the body carries per-request dynamic content.
func RatioSimilar(a, b ResponseSignature) bool {
	if a.StatusCode != b.StatusCode {
		return false
	}
	if a.BodyHash == b.BodyHash {
		return true
	}
	return QuickRatio(a, b) >= UpperRatioBound
}

// BodiesSimilar reports whether two response bodies are textually equivalent
// (QuickRatio >= UpperRatioBound), ignoring status — callers that also care about
// status gate on it separately. Two empty bodies are treated as similar. It is
// the body-only counterpart to RatioSimilar (which additionally requires an equal
// status) and centralizes the "same page?" check shared by the re-confirmation
// gates (jwt/csrf accepted-as-baseline, forbidden/nginx/firebase stability).
func BodiesSimilar(a, b string) bool {
	return QuickRatio(newRatioSignature(a), newRatioSignature(b)) >= UpperRatioBound
}

// IsDifferent returns true if two signatures are meaningfully different by the
// fast length/hash/status pre-filter (a different status, or a >100 byte / >20%
// body-length gap). It does not consider token similarity — callers wanting the
// dynamic-content-robust check should also use QuickRatio.
func IsDifferent(a, b ResponseSignature) bool {
	if a.StatusCode != b.StatusCode {
		return true
	}
	if a.BodyHash == b.BodyHash {
		return false
	}
	diff := absInt(a.BodyLength - b.BodyLength)
	if diff > SubstantialBodyDeltaBytes {
		return true
	}
	maxLen := max(a.BodyLength, b.BodyLength)
	if maxLen > 0 && float64(diff)/float64(maxLen) > SubstantialBodyDeltaRatio {
		return true
	}
	return false
}

// HasSubstantialBodyDifference reports a large, content-driven length gap: the
// bodies must differ by both an absolute (>SubstantialBodyDeltaBytes) and a
// relative (>=SubstantialBodyDeltaRatio) margin.
func HasSubstantialBodyDifference(a, b ResponseSignature) bool {
	if a.BodyHash == b.BodyHash {
		return false
	}
	diff := absInt(a.BodyLength - b.BodyLength)
	if diff <= SubstantialBodyDeltaBytes {
		return false
	}
	maxLen := max(a.BodyLength, b.BodyLength)
	if maxLen == 0 {
		return false
	}
	return float64(diff)/float64(maxLen) >= SubstantialBodyDeltaRatio
}

// absInt returns the absolute value of n.
func absInt(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

// SizeShiftGap reports whether a payload reproducibly shifts the response size
// outside the page's natural variance. Given the lengths of two no-payload
// samples (baselineLen, controlLen) and two with-payload samples (probeLen,
// probe2Len), it returns the gap by which the with-payload band sits entirely on
// ONE side of, and clear of, the no-payload band — and whether that gap exceeds
// the variance threshold max(30% of baselineLen, 256 bytes). When the two bands
// overlap (jitter) or the gap is within the threshold, gap is 0 and ok is false.
func SizeShiftGap(baselineLen, controlLen, probeLen, probe2Len int) (gap int, ok bool) {
	noHdrMin, noHdrMax := min(baselineLen, controlLen), max(baselineLen, controlLen)
	probeMin, probeMax := min(probeLen, probe2Len), max(probeLen, probe2Len)

	switch {
	case probeMin > noHdrMax:
		gap = probeMin - noHdrMax // payload consistently enlarges the response
	case probeMax < noHdrMin:
		gap = noHdrMin - probeMax // payload consistently shrinks the response
	default:
		return 0, false // bands overlap → jitter, not the payload
	}

	threshold := baselineLen * 30 / 100
	if threshold < 256 {
		threshold = 256
	}
	if gap <= threshold {
		return 0, false
	}
	return gap, true
}

// ----------------------------------------------------------------------------
// High-level re-confirmation strategies
// ----------------------------------------------------------------------------

// ReconfirmConfig tunes the body-differential re-confirmation.
type ReconfirmConfig struct {
	// PayloadRounds is how many times the payload request is replayed to confirm
	// its response is reproducible. Minimum (and default) is 2.
	PayloadRounds int
	// NoRedirects controls whether the requester follows 3xx. Default true so a
	// redirect isn't transparently followed and mistaken for a content diff.
	NoRedirects bool
	// Evidence, when non-nil, collects the request/response pairs this helper
	// fetches (each payload replay and the fresh baseline) so the module can
	// attach the confirmation evidence to its finding instead of discarding it.
	// nil-safe: leave unset to skip evidence capture.
	Evidence *EvidenceCollector
}

func (c ReconfirmConfig) withDefaults() ReconfirmConfig {
	if c.PayloadRounds < 2 {
		c.PayloadRounds = 2
	}
	return c
}

// BodyDifferentialResult is the outcome of ConfirmBodyDifferential.
type BodyDifferentialResult struct {
	// Confirmed is true only when the payload reproducibly introduced new content
	// that is absent from the clean baseline.
	Confirmed bool
	// Ran is false when an HTTP/parse error prevented reaching a verdict. Callers
	// should fail-open (keep the finding) on !Ran rather than dropping it, so a
	// transient network error does not silently discard a true positive.
	Ran bool
	// Reason is a short human-readable explanation, suitable for debug logging.
	Reason string
}

// ConfirmBodyDifferential re-issues a payload-applied request and a clean
// (no-payload) baseline and reports whether the payload reproducibly introduces
// new content that is absent from the baseline — directly answering "does the
// response actually differ with the payload applied vs not?".
//
// It uses an "introduced-content" differential rather than a whole-page
// dissimilarity check, so it is false-negative safe for small but real signals
// (a single reflected marker / math result / injected header in a large page),
// while still catching the classic false-positive causes:
//   - the payload had no observable in-band effect (response ≡ baseline);
//   - the only differences are per-request dynamic noise (not stable across the
//     payload replays);
//   - the "marker" the module keyed on was actually present in the baseline too
//     (a coincidental page match).
//
// Because the comparison is over the full raw response (status line + headers +
// body, with volatile headers stripped), a payload-induced status change or
// header/Location injection is naturally captured as introduced content rather
// than being mistaken for, or rejected as, a body diff.
//
// cachedBaselineBody/cachedBaselineStatus is an already-fetched clean response
// (e.g. the executor's pre-scan baseline). When present it is folded into the
// baseline so a token must be absent from BOTH baseline samples to count as
// introduced — making the verdict robust against a dynamic baseline. Pass "" / 0
// to skip.
func ConfirmBodyDifferential(
	client *http.Requester,
	service *httpmsg.Service,
	payloadRaw, baselineRaw []byte,
	cachedBaselineBody string,
	cachedBaselineStatus int,
	cfg ReconfirmConfig,
) BodyDifferentialResult {
	cfg = cfg.withDefaults()
	if client == nil || len(payloadRaw) == 0 || len(baselineRaw) == 0 {
		return BodyDifferentialResult{Ran: false, Reason: "missing client or request data"}
	}

	// Parse the payload request once; it is replayed PayloadRounds times below.
	payloadReq, err := httpmsg.ParseRawRequest(string(payloadRaw))
	if err != nil {
		return BodyDifferentialResult{Ran: false, Reason: "payload request parse failed"}
	}
	if service != nil {
		payloadReq = payloadReq.WithService(service)
	}

	// Replay the payload request; collect the introduced-content token set of each
	// replay so per-request dynamic tokens (varying run-to-run) drop out.
	payloadTokenSets := make([]map[string]int, 0, cfg.PayloadRounds)
	for i := 0; i < cfg.PayloadRounds; i++ {
		_, raw, ok := fetchResponseParsed(client, payloadReq, cfg.NoRedirects)
		if !ok {
			return BodyDifferentialResult{Ran: false, Reason: "payload request fetch failed"}
		}
		cfg.Evidence.Add(fmt.Sprintf("confirm-payload round %d", i+1), string(payloadRaw), raw)
		payloadTokenSets = append(payloadTokenSets, deltaTokenSet(raw))
	}

	// Fetch a fresh clean baseline.
	_, baseRaw, ok := fetchResponse(client, service, baselineRaw, cfg.NoRedirects)
	if !ok {
		return BodyDifferentialResult{Ran: false, Reason: "baseline request fetch failed"}
	}
	cfg.Evidence.Add("confirm-baseline", string(baselineRaw), baseRaw)

	// Fold every baseline sample (fresh + cached) into one token set: a token
	// must be absent from all of them to be considered payload-introduced.
	baseTokens := deltaTokenSet(baseRaw)
	if cachedBaselineStatus > 0 && cachedBaselineBody != "" {
		for tok, n := range deltaTokenSet(cachedBaselineBody) {
			baseTokens[tok] += n
		}
	}

	// Introduced content = tokens present in EVERY payload replay (stable, not
	// dynamic noise) and absent from the baseline (genuinely payload-driven).
	introduced := 0
	for tok := range payloadTokenSets[0] {
		if baseTokens[tok] > 0 {
			continue
		}
		inAllReplays := true
		for i := 1; i < len(payloadTokenSets); i++ {
			if payloadTokenSets[i][tok] == 0 {
				inAllReplays = false
				break
			}
		}
		if inAllReplays {
			introduced++
		}
	}

	if introduced == 0 {
		return BodyDifferentialResult{
			Ran: true, Confirmed: false,
			Reason: "payload introduced no stable content absent from baseline (no effect, dynamic noise, or marker already in baseline)",
		}
	}

	return BodyDifferentialResult{Ran: true, Confirmed: true, Reason: "payload reproducibly introduced content absent from baseline"}
}

// volatileHeaderLine matches per-request response header lines whose values
// change every request (timestamps, ids, sizes, cookies). They are stripped
// before the introduced-content diff so they don't masquerade as payload-driven
// new content.
var volatileHeaderLine = regexp.MustCompile(`(?im)^(date|set-cookie|etag|age|expires|last-modified|content-length|keep-alive|x-request-id|x-amz-[^:]*|cf-ray|x-trace[^:]*|x-runtime|x-served-by|report-to|nel|cf-cache-status):.*$`)

// deltaTokenSet builds a token-count multiset over a cleaned full raw response
// for introduced-content comparison. Unlike NewResponseSignature it keeps short
// digit runs (so numeric markers like a template math result survive) and only
// collapses very long hex/digit runs (ids/hashes). Single-character tokens are
// dropped to reduce noise.
func deltaTokenSet(raw string) map[string]int {
	s := strings.ToLower(capForRatio(raw))
	s = volatileHeaderLine.ReplaceAllString(s, " ")
	s = reVeryLongHexRun.ReplaceAllString(s, " ")
	counts := make(map[string]int)
	for _, tok := range reNonWord.Split(s, -1) {
		if len(tok) < 2 {
			continue
		}
		counts[tok]++
	}
	return counts
}

// reVeryLongHexRun collapses only very long hex runs (≥16 chars: session ids,
// hashes, nonces — the [0-9a-f] class also covers long pure-digit runs) while
// preserving short numeric markers like a template math result.
var reVeryLongHexRun = regexp.MustCompile(`[0-9a-f]{16,}`)

// ExecuteRaw parses a raw request, binds it to service (when non-nil), executes
// it with the given options, and returns the response status and body. ok is
// false on any build/transport error or a nil response. It centralizes the
// re-confirmation fetch idiom — notably the NoClustering discipline — shared by
// the active modules' confirmation helpers, so each call site no longer
// re-derives (and risks forgetting) it.
func ExecuteRaw(client *http.Requester, service *httpmsg.Service, rawReq []byte, opts http.Options) (status int, body string, ok bool) {
	req, err := httpmsg.ParseRawRequest(string(rawReq))
	if err != nil {
		return 0, "", false
	}
	if service != nil {
		req = req.WithService(service)
	}
	resp, _, err := client.Execute(req, opts)
	if err != nil {
		return 0, "", false
	}
	defer resp.Close()
	if resp.Response() == nil {
		return 0, "", false
	}
	return resp.Response().StatusCode, resp.Body().String(), true
}

// fetchResponse re-issues a raw request and returns its status code and full raw
// response string (status line + headers + body, so header/Location injections
// are visible). The bool is false on any parse/HTTP/empty-response error.
func fetchResponse(client *http.Requester, service *httpmsg.Service, raw []byte, noRedirects bool) (int, string, bool) {
	req, err := httpmsg.ParseRawRequest(string(raw))
	if err != nil {
		return 0, "", false
	}
	if service != nil {
		req = req.WithService(service)
	}
	return fetchResponseParsed(client, req, noRedirects)
}

// fetchResponseParsed is fetchResponse for an already-parsed (and service-bound)
// request. Confirmation helpers that replay the SAME request across multiple
// rounds parse the raw once and reuse the parsed request here, instead of
// re-parsing per round. The request is treated as immutable by Execute.
func fetchResponseParsed(client *http.Requester, req *httpmsg.HttpRequestResponse, noRedirects bool) (int, string, bool) {
	// NoClustering bypasses the requester's 500ms response cache. These
	// confirmation replays run back-to-back (well within the TTL); a cached replay
	// would return a byte-identical response and collapse the measured run-to-run
	// variance to zero — making dynamic noise look like stable introduced content
	// and defeating the very differential this helper exists to compute.
	resp, _, err := client.Execute(req, http.Options{NoRedirects: noRedirects, NoClustering: true})
	if err != nil {
		return 0, "", false
	}
	defer resp.Close()
	if resp.Response() == nil {
		return 0, "", false
	}
	return resp.Response().StatusCode, resp.FullResponseString(), true
}

// ReflectionProbe sends a request carrying the given fresh canary and reports
// whether the canary was observed reflected the way the module cares about
// (e.g. in a response header, the Location header, or the body). An error
// aborts the multi-round confirmation.
type ReflectionProbe func(canary string) (reflected bool, err error)

// ConfirmReflection runs probe across `rounds` (minimum 2) with a fresh random
// canary each round, and returns true only if EVERY round observed the canary
// reflected. Using a fresh random canary per round makes a coincidental static
// match astronomically unlikely, so this doubles as a payload-applied-vs-not
// differential: a value that genuinely flows from input to output reflects
// every time, while a page that merely happens to contain a fixed string does
// not track the changing canary.
func ConfirmReflection(rounds int, probe ReflectionProbe) (bool, error) {
	if rounds < 2 {
		rounds = 2
	}
	for i := 0; i < rounds; i++ {
		reflected, err := probe(FreshCanary())
		if err != nil {
			return false, err
		}
		if !reflected {
			return false, nil
		}
	}
	return true, nil
}

// FreshCanary returns a short random alphanumeric token (alpha-leading, safe to
// embed in URLs, headers, and HTML) for reflection probes.
func FreshCanary() string {
	return "vgo" + randomToken(10)
}

// ConfirmNotSoft404 reports whether a marker-matched response is a genuine hit
// rather than a soft-404 / SPA wildcard shell or a redirect to an auth page.
// It returns true when the response looks like a real, specific resource.
//
//   - probeReq: any request to the same host (used to fetch and cache the host's
//     wildcard fingerprint via WildcardProbe).
//   - statusCode/body: the response that matched the module's content marker.
//   - location: the matched response's Location header (may be empty).
//
// On a wildcard-probe error it fails open (returns true) so a transient probe
// failure does not suppress a real finding.
func ConfirmNotSoft404(
	sc *ScanContext,
	client *http.Requester,
	probeReq *httpmsg.HttpRequestResponse,
	statusCode int,
	body []byte,
	location string,
) bool {
	// A 3xx redirect to a login/auth page is not a real exposure. Reuses the
	// shared login-redirect detector so detection stays consistent with the
	// authz/idor/bfla modules.
	if authzutil.IsLoginRedirect(statusCode, location) {
		return false
	}
	if sc == nil {
		return true
	}
	entry, err := sc.WildcardProbe(probeReq, client)
	if err != nil || entry == nil {
		return true // fail open — never suppress on a probe failure
	}
	if entry.MatchesBody(statusCode, body) {
		return false // just the SPA / soft-404 shell
	}
	return true
}

// ----------------------------------------------------------------------------
// Cross-identifier determinism gate (IDOR / BOLA false-positive suppression)
// ----------------------------------------------------------------------------

// CrossIDConfig tunes the cross-identifier determinism gate.
type CrossIDConfig struct {
	// SelfRounds is how many times the ORIGINAL (unchanged-id) request is
	// re-issued to measure the endpoint's same-id response variation. Minimum
	// (and default) is 2.
	SelfRounds int
	// NoRedirects controls whether the requester follows 3xx during the
	// self-refetch. Default false so the refetch mirrors the IDOR modules'
	// probes, which follow redirects.
	NoRedirects bool
	// Evidence, when non-nil, collects the same-id refetch responses used to
	// measure the endpoint's determinism, so the module can attach the
	// determinism evidence to its finding. nil-safe: leave unset to skip.
	Evidence *EvidenceCollector
}

func (c CrossIDConfig) withDefaults() CrossIDConfig {
	if c.SelfRounds < 2 {
		c.SelfRounds = 2
	}
	return c
}

// CrossIDVerdict is the outcome of ConfirmCrossIDDifferential.
type CrossIDVerdict struct {
	// Trustworthy reports whether the changed-identifier response diverges from
	// the baseline by a meaningfully larger margin than the baseline diverges
	// from itself across same-id refetches — i.e. the difference is attributable
	// to the changed identifier rather than to per-request dynamic noise.
	Trustworthy bool
	// Ran is false when an HTTP/parse error prevented reaching a verdict. Callers
	// should fail-open (keep the finding) on !Ran so a transient network error
	// does not silently discard a true positive.
	Ran bool
	// SelfRatio is the LOWEST same-id similarity observed across the refetches
	// (1.0 = perfectly deterministic; lower = the endpoint varies its own
	// response for an unchanged id). CrossRatio is the baseline-vs-probe
	// similarity. Both are exposed for finding metadata / debug logging.
	SelfRatio  float64
	CrossRatio float64
	Reason     string
}

// ConfirmCrossIDDifferential decides whether a candidate IDOR/BOLA difference is
// real or an artifact of a non-deterministic endpoint.
//
// It re-issues the ORIGINAL (unchanged-id) request SelfRounds times and measures
// how much the endpoint's response varies for the SAME identifier, then compares
// that self-variation against the variation observed when the identifier was
// changed (baseline vs probe). The verdict is Trustworthy only when the
// changed-id response is at least RatioDiffTolerance LESS similar to the baseline
// than the worst same-id refetch is (a status flap across refetches forces the
// endpoint to be treated as fully non-deterministic).
//
// This suppresses the classic IDOR false positive on endpoints that return
// different content on every request regardless of the object id — analytics
// beacons, tracking pixels, ad rotators, randomized/obfuscated JS bundles —
// where a changed-id response looks "structurally similar but different" exactly
// like a real broken-object-level authorization would. Because both ratios are
// taken against the same baseline, any slow drift in the endpoint cancels out
// and only the identifier's effect remains.
//
// Unlike the introduced-content differential (ConfirmBodyDifferential), the
// similarity here deliberately does NOT collapse dynamic hex/digit runs: an
// endpoint's non-determinism usually lives precisely in those runs (nonces,
// counters, random ids), and collapsing them would hide the very instability the
// gate exists to detect.
func ConfirmCrossIDDifferential(
	client *http.Requester,
	service *httpmsg.Service,
	originalRaw []byte,
	baselineBody string,
	baselineStatus int,
	probeBody string,
	cfg CrossIDConfig,
) CrossIDVerdict {
	cfg = cfg.withDefaults()
	baseSig := rawBodySignature(baselineStatus, baselineBody)
	crossRatio := QuickRatio(baseSig, rawBodySignature(baselineStatus, probeBody))

	if client == nil || len(originalRaw) == 0 {
		return CrossIDVerdict{Ran: false, CrossRatio: crossRatio, Reason: "missing client or original request"}
	}

	// Parse the original request once; it is replayed SelfRounds times below.
	originalReq, err := httpmsg.ParseRawRequest(string(originalRaw))
	if err != nil {
		return CrossIDVerdict{Ran: false, CrossRatio: crossRatio, Reason: "same-id request parse failed"}
	}
	if service != nil {
		originalReq = originalReq.WithService(service)
	}

	selfRatio := 1.0
	for i := 0; i < cfg.SelfRounds; i++ {
		status, body, ok := fetchResponseBodyParsed(client, originalReq, cfg.NoRedirects)
		if !ok {
			return CrossIDVerdict{Ran: false, CrossRatio: crossRatio, Reason: "same-id refetch failed"}
		}
		cfg.Evidence.Add(fmt.Sprintf("confirm-original round %d", i+1), string(originalRaw), body)
		// A status flap for an unchanged id means the endpoint is non-deterministic
		// at the status level — treat it as maximally unstable.
		if status != baselineStatus {
			selfRatio = 0
			continue
		}
		if r := QuickRatio(baseSig, rawBodySignature(status, body)); r < selfRatio {
			selfRatio = r
		}
	}

	trustworthy := selfRatio-crossRatio >= RatioDiffTolerance
	reason := "changed-id difference exceeds same-id noise envelope"
	if !trustworthy {
		reason = "changed-id difference within same-id noise envelope (non-deterministic endpoint)"
	}
	return CrossIDVerdict{
		Trustworthy: trustworthy,
		Ran:         true,
		SelfRatio:   selfRatio,
		CrossRatio:  crossRatio,
		Reason:      reason,
	}
}

// rawBodySignature builds a ResponseSignature whose token multiset is NOT
// noise-collapsed (unlike NewResponseSignature): per-request dynamic runs
// (nonces, timestamps, random hex/digit ids) remain distinct tokens. This is
// deliberate for the determinism gate — a non-deterministic endpoint's
// variability lives precisely in those runs, so collapsing them would make a
// random endpoint look stable and defeat the gate.
func rawBodySignature(status int, body string) ResponseSignature {
	counts, total := Tokenize(strings.ToLower(body))
	return ResponseSignature{
		StatusCode:  status,
		BodyLength:  len(body),
		tokenCounts: counts,
		tokenTotal:  total,
	}
}

// fetchResponseBody re-issues a raw request and returns its status code and body
// string (a copy, safe to retain after the response is closed). The bool is
// false on any parse/HTTP/empty-response error.
func fetchResponseBody(client *http.Requester, service *httpmsg.Service, raw []byte, noRedirects bool) (int, string, bool) {
	req, err := httpmsg.ParseRawRequest(string(raw))
	if err != nil {
		return 0, "", false
	}
	if service != nil {
		req = req.WithService(service)
	}
	return fetchResponseBodyParsed(client, req, noRedirects)
}

// fetchResponseBodyParsed is fetchResponseBody for an already-parsed (and
// service-bound) request, so a same-id determinism loop parses the raw once and
// replays the parsed request across rounds. The request is immutable to Execute.
func fetchResponseBodyParsed(client *http.Requester, req *httpmsg.HttpRequestResponse, noRedirects bool) (int, string, bool) {
	// NoClustering bypasses the 500ms response cache so each same-id refetch is a
	// genuinely fresh observation. A cached replay would report perfect self-
	// similarity (selfRatio≈1.0) and make a non-deterministic endpoint look stable,
	// defeating the determinism gate.
	resp, _, err := client.Execute(req, http.Options{NoRedirects: noRedirects, NoClustering: true})
	if err != nil {
		return 0, "", false
	}
	defer resp.Close()
	if resp.Response() == nil {
		return 0, "", false
	}
	return resp.Response().StatusCode, resp.Body().String(), true
}

// ConfirmMatchReproduces re-confirms that a regex-matched server-side error/leak
// signature was genuinely introduced by an injected payload rather than ambient
// page noise (a per-request random token, a static error string, or a signature a
// stale baseline happened to miss). It is the shared confirmation gate behind the
// error-based injection modules (sqli-error-based, nosqli-error-based, …).
//
// re must (1) reproduce when payloadRaw is re-sent on a genuine application error
// surface — non-blocked and not a 404/redirect, so a coincidental match against a
// token that differs on the re-send fails this — and (2) be ABSENT from a fresh,
// non-blocked control fetch of the insertion point's original value, so an error
// the endpoint returns for ANY input is rejected even when the captured baseline
// missed it.
//
// It fails open (returns true) on a transport error so a transient failure never
// suppresses a true positive, and drops the finding (returns false) when the
// re-fetch is blocked or not an error surface, or the control is blocked: such a
// page can neither reproduce the leak nor serve as a clean control. A nil re is
// treated as "nothing to re-confirm" and passes.
func ConfirmMatchReproduces(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	httpClient *http.Requester,
	payloadRaw []byte,
	re *regexp.Regexp,
) bool {
	if re == nil {
		return true
	}
	// (1) Reproducible under the payload, on a genuine (non-blocked, error-surface) response.
	body, blocked, surface, ok := errorSurfaceFetch(ctx, httpClient, payloadRaw)
	if !ok {
		return true
	}
	if blocked || !surface || !re.MatchString(body) {
		return false
	}
	// (2) Absent from a fresh, non-blocked control fetch of the original value.
	controlBody, controlBlocked, _, ok := errorSurfaceFetch(ctx, httpClient, ip.BuildRequest([]byte(ip.BaseValue())))
	if !ok {
		return true
	}
	if controlBlocked {
		return false
	}
	return !re.MatchString(controlBody)
}

// errorSurfaceFetch re-issues a raw request and reports its body, whether it was a
// WAF/CDN/rate-limit page (infra.IsBlockedResponse), and whether its status is an
// application error surface rather than a 404/redirect (infra.IsErrorSurfaceStatus).
// ok is false on any parse/HTTP error. NoClustering forces a fresh origin
// round-trip: the request-clustering cache would otherwise replay the identical
// captured response, so a coincidental match against a per-request random token
// would "reproduce" from cache instead of revealing itself as one-off noise.
func errorSurfaceFetch(ctx *httpmsg.HttpRequestResponse, httpClient *http.Requester, raw []byte) (body string, blocked, surface, ok bool) {
	req, err := httpmsg.ParseRawRequest(string(raw))
	if err != nil {
		return "", false, false, false
	}
	req = req.WithService(ctx.Service())
	resp, _, err := httpClient.Execute(req, http.Options{NoClustering: true})
	if err != nil {
		return "", false, false, false
	}
	defer resp.Close()
	return resp.Body().String(), infra.IsBlockedResponse(resp), infra.IsErrorSurfaceStatus(resp), true
}
