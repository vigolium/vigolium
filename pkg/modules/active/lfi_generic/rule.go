package lfi_generic

import (
	"regexp"
	"strings"
)

// injectionMarker is the sentinel carried in a comment of the PHP the data://
// and php://input execution probes include (phpEchoProduct). It lets
// corroboration steps recognise — and discard — our own payload when a target
// merely *reflects* the request (e.g. Salesforce Aura endpoints echo
// aura.context): without it the reflected base64 decodes straight back to PHP
// and masquerades as a php://filter source read. It is never evidence on its
// own; execution is proven by the probe's computed product.
const injectionMarker = "vigolium-test"

type rule struct {
	payloads []rulePayload
	regex    []*regexp.Regexp
	words    []string
	// confirm is an optional, payload-specific corroboration step run in
	// addition to words/regex. It receives the fuzzed response body, the
	// original (baseline) body, and the payload that was injected, and returns
	// true only when the body carries strong, module-specific evidence of a
	// successful include (e.g. a base64 blob that decodes to actual PHP source,
	// or two distinct .env assignments). It exists to replace loose signature
	// regexes/words that fire on incidental base64 (data-URI images, fonts) or
	// the payload simply being reflected back in the response.
	confirm func(data, baseline, payload string) bool
}

func newRule(payloads []string, regex []*regexp.Regexp, words []string) *rule {
	r := &rule{regex: regex, words: words}
	for _, p := range payloads {
		r.payloads = append(r.payloads, rulePayload{value: p})
	}
	return r
}

// rulePayload is one payload and whether it is already percent-encoded the
// way it must reach the server (built through httpmsg.BuildPreEncoded so its
// own encoding is not double-encoded).
type rulePayload struct {
	value      string
	preEncoded bool
}

// withPreEncoded appends payloads that carry their own percent-encoding
// (%00, %252e, overlong %C0%AE, %u002e).
func (r *rule) withPreEncoded(payloads ...string) *rule {
	for _, p := range payloads {
		r.payloads = append(r.payloads, rulePayload{value: p, preEncoded: true})
	}
	return r
}

// withConfirm attaches a payload-specific corroboration step to the rule.
func (r *rule) withConfirm(fn func(data, baseline, payload string) bool) *rule {
	r.confirm = fn
	return r
}

// MatchWithBaseline checks if data matches the rule but the match is NOT already
// present in the baseline. payload is the value that was injected into the
// insertion point; confirm steps use it to discard pure payload reflections.
func (r *rule) MatchWithBaseline(data, baseline, payload string) bool {
	if len(r.words) > 0 {
		allWordsFound := true
		allWordsInBaseline := true
		for _, word := range r.words {
			if !strings.Contains(data, word) {
				allWordsFound = false
				break
			}
			if !strings.Contains(baseline, word) {
				allWordsInBaseline = false
			}
		}
		if allWordsFound && !allWordsInBaseline {
			return true
		}
	}
	if len(r.regex) > 0 {
		for _, regex := range r.regex {
			if regex.MatchString(data) {
				if baseline != "" && regex.MatchString(baseline) {
					continue
				}
				return true
			}
		}
	}
	if r.confirm != nil && r.confirm(data, baseline, payload) {
		return true
	}
	return false
}

func (r *rule) Match(data string) bool {
	if len(r.words) > 0 {
		allWordsFound := true
		for _, word := range r.words {
			if !strings.Contains(data, word) {
				allWordsFound = false
				break
			}
		}
		if allWordsFound {
			return true
		}
	}
	if len(r.regex) > 0 {
		for _, regex := range r.regex {
			if regex.MatchString(data) {
				return true
			}
		}
	}
	return false
}

func (r *rule) Payloads() []rulePayload {
	return r.payloads
}
