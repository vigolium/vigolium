package nosqli_operator_injection

import (
	"regexp"
	"strings"
	"time"
)

// nosqlErrorPatterns are used to skip findings when the response contains NoSQL error messages
// (those are handled by nosqli_error_based module instead).
var nosqlErrorPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)MongoError|BSON|mongod|MongoClient|TopologyDescription`),
	regexp.MustCompile(`(?i)E11000 duplicate key|cannot index parallel arrays|\$where requires`),
	regexp.MustCompile(`(?i)couchdb|org\.apache\.couchdb`),
	regexp.MustCompile(`(?i)com\.datastax\.driver|InvalidRequestException|SyntaxException.*CQL`),
}

const (
	// timeBasedSleepMs is the value passed to MongoDB's sleep() in the $where
	// payload. MongoDB sleep() takes milliseconds, so 10000 == 10 seconds. A
	// delay that large is well beyond any realistic network jitter or ambient
	// endpoint slowness, so a consistent hit is strong evidence of injection.
	timeBasedSleepMs = 10000
	// timeDelayThresholdMs is the minimum delta (ms) over baseline required to
	// count a single probe as delayed. Set to 70% of the injected sleep so we
	// still flag the hit if the server does partial/jittery scheduling but
	// won't fire on generic slowness.
	timeDelayThresholdMs = 7000
	// timeBasedConfirmationRounds is how many consecutive probes must each
	// exceed the threshold before the finding is reported. Guards against a
	// single unusually slow response being misread as injection.
	timeBasedConfirmationRounds = 3
	sizeIncreasePercent         = 50  // percent body size increase to consider data exfiltration
	sizeIncreaseMinBytes        = 200 // minimum absolute increase in bytes

	// sizeDivergeMax is the maximum normalized clean-vs-payload similarity that
	// can still count as exfiltrated data. At or above it the larger payload
	// response is structurally the SAME content as the clean response (a static
	// page that merely measured bigger — e.g. an SSO login page, or a gzip /
	// capture-encoding asymmetry), not new data pulled by the operator.
	sizeDivergeMax = 0.95

	// Boolean-diff thresholds. Detection compares always-true vs always-false
	// responses, but only after sampling EACH condition several times so the
	// endpoint's intrinsic per-request variance is measured directly (rather than
	// inferred from a single re-probe) — a CDN that randomly flaps between a cached
	// object and a block page would otherwise let a phantom true/false difference
	// through.
	//
	// booleanStabilityMin is the minimum normalized similarity each condition must
	// show under identical input across its own samples. Below it the endpoint is
	// non-deterministic (rotating tokens, nonces, timestamps, randomized content)
	// and any true/false difference is noise.
	booleanStabilityMin = 0.92
	// booleanDivergeMax is the maximum normalized true-vs-false similarity that can
	// still count as a signal — the false condition must clearly diverge.
	booleanDivergeMax = 0.85
	// booleanMarginMin is how much the true/false divergence must exceed the
	// endpoint's own same-condition variance before it is believed.
	booleanMarginMin = 0.10

	// boolTrueSamples / boolFalseSamples are how many times each condition is
	// re-sent (interleaved). Multiple samples per condition turn a one-shot
	// comparison into a reproducibility test: a real injection keeps every
	// always-true response mutually similar and every always-false response
	// mutually similar while the two clusters stay apart; a randomizing endpoint
	// fails the same-condition similarity check and is dropped.
	boolTrueSamples  = 3
	boolFalseSamples = 2
)

// booleanDiffPair couples an always-true probe with the STRUCTURALLY MATCHING
// always-false probe (same quote style, same injection shape). The two differ
// ONLY in the boolean result of the injected condition, so in a vulnerable
// endpoint the true probe returns data and the false probe does not while every
// other request attribute is held constant. The previous positional pairing
// (boolPayloads[i] vs boolPayloads[i+1]) silently compared two always-true
// payloads against each other — a guaranteed false-positive generator on any
// non-deterministic endpoint.
type booleanDiffPair struct {
	truePayload  string
	falsePayload string
	desc         string
}

// booleanDiffPairs is the source of truth for the boolean-differential probes.
var booleanDiffPairs = []booleanDiffPair{
	{`' || '1'=='1`, `' || '1'=='2`, "NoSQL string injection — single-quote OR tautology"},
	{`" || "1"=="1`, `" || "1"=="2`, "NoSQL string injection — double-quote OR tautology"},
	{`'; return true; var a='`, `'; return false; var a='`, "NoSQL JS injection — return true vs false"},
	{`"; return true; var a="`, `"; return false; var a="`, "NoSQL JS injection — return true vs false (double-quote)"},
}

// binaryContentTypePrefixes mark a response body that is NOT analyzable text. A
// boolean text differential over binary content (an image, font, archive) is
// meaningless: two different image payloads normalize to gibberish that always
// looks "divergent", manufacturing a finding. This is the motivating false
// positive — an Adobe Scene7/Akamai dynamic-image endpoint (?$preset$) returning
// WEBP bytes whose CanProcess content-type gate saw only the text/html block-page
// baseline, never the binary probe responses.
var binaryContentTypePrefixes = []string{
	"image/", "audio/", "video/", "font/",
	"application/octet-stream", "application/pdf", "application/zip",
	"application/gzip", "application/x-protobuf", "application/grpc",
}

// isBinaryContentType reports whether a Content-Type names a non-text body.
func isBinaryContentType(contentType string) bool {
	ct := strings.ToLower(contentType)
	for _, p := range binaryContentTypePrefixes {
		if strings.Contains(ct, p) {
			return true
		}
	}
	return false
}

// looksBinary sniffs a response body for binary content when the Content-Type is
// missing or misleading. A NUL byte is decisive; otherwise a high ratio of
// control bytes (excluding tab/newline/CR) in the leading window marks it binary.
// High bytes (0x80+) are left uncounted so valid UTF-8 text is never misread.
func looksBinary(body string) bool {
	if body == "" {
		return false
	}
	n := len(body)
	if n > 2048 {
		n = 2048
	}
	nonText := 0
	for i := 0; i < n; i++ {
		c := body[i]
		switch {
		case c == 0:
			return true
		case c == 0x09 || c == 0x0a || c == 0x0d:
			// tab / newline / carriage-return — text
		case c < 0x20 || c == 0x7f:
			nonText++
		}
	}
	return float64(nonText)/float64(n) > 0.10
}

// volatileTokenRe matches long opaque tokens (base64/hex/IDs/CSRF/nonces) that
// rotate per request and would otherwise make two structurally identical
// responses look different.
var volatileTokenRe = regexp.MustCompile(`[A-Za-z0-9_\-+/=]{12,}`)

// digitsRe and wsRe strip numbers (timestamps, counters) and collapse whitespace.
var (
	digitsRe = regexp.MustCompile(`\d+`)
	wsRe     = regexp.MustCompile(`\s+`)
)

// normalizeResponse removes per-request noise so two responses can be compared
// for structural rather than incidental differences. Both sides are stripped
// identically, so genuine structural divergence survives while rotating tokens,
// timestamps, and counters do not.
func normalizeResponse(body string) string {
	s := volatileTokenRe.ReplaceAllString(body, "")
	s = digitsRe.ReplaceAllString(s, "")
	s = wsRe.ReplaceAllString(s, " ")
	return strings.TrimSpace(s)
}

// diceSimilarity returns the Sørensen–Dice coefficient over character bigrams of
// a and b, in [0,1]. It is robust to small edits and length changes and cheap to
// compute (linear in input size).
func diceSimilarity(a, b string) float64 {
	if a == b {
		return 1
	}
	if len(a) < 2 || len(b) < 2 {
		return 0
	}
	bigrams := func(s string) map[string]int {
		m := make(map[string]int, len(s))
		for i := 0; i+1 < len(s); i++ {
			m[s[i:i+2]]++
		}
		return m
	}
	am, bm := bigrams(a), bigrams(b)
	overlap := 0
	for g, ca := range am {
		if cb, ok := bm[g]; ok {
			overlap += min(ca, cb)
		}
	}
	total := (len(a) - 1) + (len(b) - 1)
	return 2 * float64(overlap) / float64(total)
}

// minPairwiseSimilarity returns the SMALLEST Sørensen–Dice similarity between any
// two of the (already-normalized) bodies — the worst-case agreement of a
// condition with itself across repeats. A single sample is trivially self-similar
// (1). It is the noise floor: if the always-true responses disagree among
// themselves the endpoint is non-deterministic and no true/false signal can be
// trusted.
func minPairwiseSimilarity(norm []string) float64 {
	if len(norm) < 2 {
		return 1
	}
	minSim := 1.0
	for i := 0; i < len(norm); i++ {
		for j := i + 1; j < len(norm); j++ {
			if s := diceSimilarity(norm[i], norm[j]); s < minSim {
				minSim = s
			}
		}
	}
	return minSim
}

// maxCrossSimilarity returns the LARGEST Sørensen–Dice similarity between any
// true sample and any false sample. Using the max is conservative: if even one
// true/false pairing fails to separate, the conditions do not cleanly diverge.
func maxCrossSimilarity(a, b []string) float64 {
	maxSim := 0.0
	for _, x := range a {
		for _, y := range b {
			if s := diceSimilarity(x, y); s > maxSim {
				maxSim = s
			}
		}
	}
	return maxSim
}

// confirmBooleanDiffMulti decides whether a set of always-true and always-false
// samples is genuine boolean-based NoSQL injection rather than endpoint noise.
// Sampling each condition several times turns the old one-shot comparison into a
// reproducibility test that survives endpoints which randomize per request.
//
//   - trueBodies are repeated responses to the SAME always-true payload; their
//     mutual similarity is the noise floor for the true condition.
//   - falseBodies are repeated responses to the matching always-false payload.
//   - baselineBody is the original (un-injected) response, if captured.
//
// A finding requires ALL of: each condition is self-consistent across its own
// samples (stable endpoint), the true and false clusters diverge clearly, that
// divergence exceeds the same-condition variance by a margin, and — when a
// baseline exists — the true condition tracks the normal response at least as
// closely as the false condition does.
func confirmBooleanDiffMulti(trueBodies, falseBodies []string, baselineBody string) bool {
	if len(trueBodies) < 2 || len(falseBodies) < 1 {
		return false // need repeated true samples to establish the noise floor
	}

	nt := make([]string, len(trueBodies))
	for i, b := range trueBodies {
		nt[i] = normalizeResponse(b)
	}
	nf := make([]string, len(falseBodies))
	for i, b := range falseBodies {
		nf[i] = normalizeResponse(b)
	}

	selfTrue := minPairwiseSimilarity(nt)  // determinism of the true condition
	selfFalse := minPairwiseSimilarity(nf) // determinism of the false condition
	crossSim := maxCrossSimilarity(nt, nf) // true vs false

	if selfTrue < booleanStabilityMin {
		return false // always-true responses disagree among themselves — noisy endpoint
	}
	if selfFalse < booleanStabilityMin {
		return false // always-false responses disagree among themselves — noisy endpoint
	}
	if crossSim > booleanDivergeMax {
		return false // false condition barely differs from true — no signal
	}
	if min(selfTrue, selfFalse)-crossSim < booleanMarginMin {
		return false // divergence does not clearly exceed the endpoint's own variance
	}

	if baselineBody != "" {
		nb := normalizeResponse(baselineBody)
		if diceSimilarity(nt[0], nb) < diceSimilarity(nf[0], nb) {
			// The always-true condition should track the normal response at least
			// as closely as the always-false condition; an inversion suggests the
			// difference is unrelated to the injected logic.
			return false
		}
	}
	return true
}

// confirmBooleanDiff is the two-true/one-false shorthand retained for callers and
// tests that only have a single re-probe; it delegates to the multi-sample logic.
func confirmBooleanDiff(trueBody1, trueBody2, falseBody, baselineBody string) bool {
	return confirmBooleanDiffMulti([]string{trueBody1, trueBody2}, []string{falseBody}, baselineBody)
}

// containsNoSQLError checks if the response body contains NoSQL error patterns.
func containsNoSQLError(body string) bool {
	for _, pattern := range nosqlErrorPatterns {
		if pattern.MatchString(body) {
			return true
		}
	}
	return false
}

// analyzeAuthBypass checks if status changed from 401/403 to 200-range.
func analyzeAuthBypass(baselineStatus, probeStatus int) bool {
	if baselineStatus == 401 || baselineStatus == 403 {
		return probeStatus >= 200 && probeStatus < 300
	}
	return false
}

// analyzeSizeIncrease checks if body grew significantly compared to baseline.
func analyzeSizeIncrease(baselineLen, probeLen int) bool {
	if baselineLen == 0 {
		return probeLen >= sizeIncreaseMinBytes
	}
	increase := probeLen - baselineLen
	if increase < sizeIncreaseMinBytes {
		return false
	}
	percentIncrease := (float64(increase) / float64(baselineLen)) * 100
	return percentIncrease >= sizeIncreasePercent
}

// responsesDiverge reports whether the payload body is structurally DIFFERENT
// from a fresh clean body, after stripping per-request noise (rotating tokens,
// timestamps, whitespace). A page that renders identically regardless of the
// injected operator — e.g. a static SSO login page — normalizes to near-identical
// text and is rejected, so a body that merely measured larger (gzip / capture
// encoding asymmetry, transient truncation) is not mistaken for exfiltrated data.
// Genuine exfiltration appends records the clean response does not contain, so it
// diverges well below the threshold.
func responsesDiverge(cleanBody, probeBody string) bool {
	nc := normalizeResponse(cleanBody)
	np := normalizeResponse(probeBody)
	if nc == "" || np == "" {
		return false
	}
	return diceSimilarity(nc, np) < sizeDivergeMax
}

// analyzeTimeDelay checks if response time is significantly slower than baseline.
func analyzeTimeDelay(baselineDuration, probeDuration time.Duration) bool {
	delta := probeDuration - baselineDuration
	return delta.Milliseconds() >= timeDelayThresholdMs
}

