package lfi_generic

import (
	"regexp"
	"strings"
)

type rule struct {
	payloads []string
	regex    []*regexp.Regexp
	words    []string
}

func newRule(payloads []string, regex []*regexp.Regexp, words []string) *rule {
	return &rule{
		payloads: payloads,
		regex:    regex,
		words:    words,
	}
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
