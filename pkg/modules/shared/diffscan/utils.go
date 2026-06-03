package diffscan

import (
	"bytes"

	"github.com/vigolium/vigolium/pkg/anomaly"
)

// allAttacksSatisfy reports whether every attack in the set has a non-nil first
// snapshot satisfying pred. An empty set, a nil attack, or a missing snapshot
// returns false: the condition cannot be confirmed, so callers stay conservative
// and do not suppress.
func allAttacksSatisfy(attacks []*Attack, pred func(*ResponseSnapshot) bool) bool {
	if len(attacks) == 0 {
		return false
	}
	for _, a := range attacks {
		if a == nil || a.FirstSnapshot == nil || !pred(a.FirstSnapshot) {
			return false
		}
	}
	return true
}

// allRedirects reports whether every confirmed response is a redirect (3xx) —
// non-evaluable bodies whose only payload-dependent part is the echoed Location
// (see ResponseSnapshot.IsRedirect).
func allRedirects(attacks []*Attack) bool {
	return allAttacksSatisfy(attacks, (*ResponseSnapshot).IsRedirect)
}

// allNonRendered reports whether every confirmed response is a context in which
// no template output could have been produced: an empty body (nothing rendered)
// or a 404 (the route/template was never reached). A break-vs-escape difference
// across such responses is header/cookie jitter, not evaluation. A pair where at
// least one side is a real rendered response (a non-empty 2xx/5xx body) is left
// alone — error-based SSTI legitimately relies on a rendered 500 error page.
func allNonRendered(attacks []*Attack) bool {
	return allAttacksSatisfy(attacks, func(s *ResponseSnapshot) bool {
		return s.IsEmptyBody() || s.IsNotFound()
	})
}

// payloadReflected reports whether the attack's own payload appears verbatim in
// its response body. A reflected payload was, by definition, not evaluated — an
// engine that evaluated `${7/1}` would emit `7`, not the literal `${7/1}` — so
// reflection is the tell that distinguishes an echoed payload from a rendered
// one. Comparison is case-insensitive because filterResponse lowercases textual
// bodies.
func payloadReflected(a *Attack) bool {
	if a == nil || a.Payload == "" || a.FirstSnapshot == nil {
		return false
	}
	body := a.FirstSnapshot.FilteredResponse
	if len(body) == 0 {
		return false
	}
	// FilteredResponse is already lowercased for textual bodies (see
	// filterResponse), so only the tiny payload is lowercased here rather than
	// allocating a second lowercased copy of a potentially large body. SSTI
	// probe payloads are symbolic/lowercase, so this still matches verbatim
	// echoes in both lowercased text and case-preserved JSON bodies.
	return bytes.Contains(body, bytes.ToLower([]byte(a.Payload)))
}

// isReflectionDrivenDiff reports whether the difference between the confirmed
// break and escape responses is fully explained by the injected payload being
// reflected verbatim into both responses rather than evaluated.
//
// Two conditions must both hold:
//
//  1. Both payloads appear verbatim in their own response body. Verbatim
//     reflection of the *escape* is the decisive tell: a template engine that
//     evaluated `${7/1}` would emit `7`, not the literal `${7/1}`, so an echoed
//     escape was never evaluated and there is no SSTI to find.
//  2. The status code is identical between break and escape. A genuine
//     error-based detection turns on a status (or body) transition driven by
//     evaluation; when the status is the same on both sides, every remaining
//     difference — body text, length, even structural attributes from the
//     payload's `<`/`%`/`#` bytes being mis-parsed as HTML — is just the echoed
//     payload, not template output.
//
// This catches the reported diff-based SSTI false positives: a constant-status
// error page (`500`/`500`) or not-found page that echoes `${7/0}` vs `${7/1}`
// and so differs only by the reflected bytes. If the status differs, the finding
// is left alone for the normal evaluation logic to judge.
func isReflectionDrivenDiff(attacks []*Attack) bool {
	if len(attacks) < 2 {
		return false
	}
	breakAttack, escapeAttack := attacks[0], attacks[1]
	if breakAttack == nil || escapeAttack == nil {
		return false
	}
	if !payloadReflected(breakAttack) || !payloadReflected(escapeAttack) {
		return false
	}
	diff := GetMergedNonMatchingFingerprints(breakAttack, escapeAttack)
	if len(diff) == 0 {
		return false
	}
	// A status-code transition is the hallmark of genuine error-based
	// evaluation; preserve the finding whenever the break and escape land on
	// different statuses.
	if diff[anomaly.STATUS_CODE.String()] {
		return false
	}
	return true
}

// nonEvaluableReason returns a short, human-readable reason when the confirmed
// break/escape pair cannot be evidence of template evaluation — the difference
// is explained by something other than the application evaluating the payload —
// or "" when the pair is a genuine, evaluable difference that should be
// reported. Checks run cheapest-first.
func nonEvaluableReason(attacks []*Attack) string {
	switch {
	case allRedirects(attacks):
		// Every confirmed response is a 3xx: the only payload-dependent part is
		// the echoed Location (reflection, not evaluation). A real 200->301
		// transition leaves a non-redirect side and is not caught here.
		return "redirect-only (non-evaluable, reflection not evaluation)"
	case allNonRendered(attacks):
		// Every confirmed response is empty-bodied or a 404: nothing rendered, so
		// a difference is jitter (e.g. a rotating Set-Cookie), not evaluation.
		return "non-rendered (empty body / 404, nothing evaluated)"
	case isReflectionDrivenDiff(attacks):
		// The break/escape difference is the payload reflected verbatim into both
		// bodies at an identical status — echoed bytes, not template output.
		return "body diff explained by verbatim payload reflection, not evaluation"
	default:
		return ""
	}
}

func CountMatches(response, match []byte) int {
	matches := 0

	start := 0
	for start < len(response) {
		index := bytes.Index(response[start:], match)
		if index == -1 {
			break
		}
		matches++
		start += index + len(match)
	}

	return matches
}
