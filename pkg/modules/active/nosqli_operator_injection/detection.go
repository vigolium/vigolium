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

	// Boolean-diff thresholds. Detection compares the always-true vs always-false
	// response, but only after establishing the endpoint's intrinsic per-request
	// variance via a stability re-probe (the always-true payload sent twice).
	//
	// booleanStabilityMin is the minimum normalized similarity the endpoint must
	// show under identical input. Below it the endpoint is non-deterministic
	// (rotating tokens, nonces, timestamps) and any true/false difference is noise.
	booleanStabilityMin = 0.92
	// booleanDivergeMax is the maximum normalized true-vs-false similarity that can
	// still count as a signal — the false condition must clearly diverge.
	booleanDivergeMax = 0.85
	// booleanMarginMin is how much the true/false divergence must exceed the
	// endpoint's own true/true variance before it is believed.
	booleanMarginMin = 0.10
)

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

// confirmBooleanDiff decides whether an always-true vs always-false probe pair is
// genuine boolean-based NoSQL injection rather than endpoint noise.
//
//   - trueBody1/trueBody2 are two responses to the SAME always-true payload; their
//     similarity establishes the endpoint's per-request variance (the noise floor).
//   - falseBody is the always-false response.
//   - baselineBody is the original (un-injected) response, if captured.
//
// A finding requires: the endpoint is stable under identical input, the false
// condition diverges clearly from the true condition, that divergence exceeds the
// noise floor by a margin, and — when a baseline exists — the true condition
// resembles the normal response at least as much as the false condition does.
func confirmBooleanDiff(trueBody1, trueBody2, falseBody, baselineBody string) bool {
	nt1 := normalizeResponse(trueBody1)
	nt2 := normalizeResponse(trueBody2)
	nf := normalizeResponse(falseBody)

	selfSim := diceSimilarity(nt1, nt2)  // endpoint determinism under identical input
	crossSim := diceSimilarity(nt1, nf)  // true vs false

	if selfSim < booleanStabilityMin {
		return false // noisy endpoint — true/false difference is meaningless
	}
	if crossSim > booleanDivergeMax {
		return false // false condition barely differs from true — no signal
	}
	if selfSim-crossSim < booleanMarginMin {
		return false // divergence does not clearly exceed the endpoint's own variance
	}

	if baselineBody != "" {
		nb := normalizeResponse(baselineBody)
		if diceSimilarity(nt1, nb) < diceSimilarity(nf, nb) {
			// The always-true condition should track the normal response at least
			// as closely as the always-false condition; an inversion suggests the
			// difference is unrelated to the injected logic.
			return false
		}
	}
	return true
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

// isAccessDenied returns true for status codes that indicate the request was
// rejected by an auth/WAF/rate-limit layer rather than served by the app.
func isAccessDenied(status int) bool {
	return status == 401 || status == 403 || status == 429 || status == 503
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

