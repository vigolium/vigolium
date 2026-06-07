package lfi_generic

import (
	"regexp"
	"strings"
)

type rule struct {
	payloads []string
	regex    []*regexp.Regexp
	words    []string
	// confirm is an optional, payload-specific corroboration step run in
	// addition to words/regex. It receives the fuzzed response body and the
	// original (baseline) body and returns true only when the body carries
	// strong, module-specific evidence of a successful include (e.g. a
	// base64 blob that decodes to actual PHP source). It exists to replace
	// loose signature regexes that fire on incidental base64 (data-URI images,
	// fonts) embedded in ordinary HTML pages.
	confirm func(data, baseline string) bool
}

func newRule(payloads []string, regex []*regexp.Regexp, words []string) *rule {
	return &rule{
		payloads: payloads,
		regex:    regex,
		words:    words,
	}
}

// withConfirm attaches a payload-specific corroboration step to the rule.
func (r *rule) withConfirm(fn func(data, baseline string) bool) *rule {
	r.confirm = fn
	return r
}

// MatchWithBaseline checks if data matches the rule but the match is NOT already present in the baseline.
func (r *rule) MatchWithBaseline(data, baseline string) bool {
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
	if r.confirm != nil && r.confirm(data, baseline) {
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

func (r *rule) Payloads() []string {
	return r.payloads
}
