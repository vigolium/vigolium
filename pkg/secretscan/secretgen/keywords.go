package main

import (
	"regexp/syntax"
	"strings"
)

// minKeywordLen is the shortest literal we accept as a prefilter keyword. Shorter
// necessary literals (e.g. "ey") are too common to be selective, so the rule
// falls back to always-run rather than risk a slow, useless keyword.
const minKeywordLen = 3

// extractKeywords derives a set of lowercased literal keywords K for a pattern
// such that ANY string matching the pattern contains at least one element of K.
// This makes the runtime keyword prefilter a sound necessary condition — a rule
// is only skipped when none of its keywords appear, which can never drop a real
// match. Returns nil when no selective necessary literal exists (rule always-run).
func extractKeywords(pat string) []string {
	re, err := syntax.Parse(pat, syntax.Perl)
	if err != nil {
		return nil
	}
	lits := requiredLiterals(re)
	if len(lits) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	var out []string
	for _, l := range lits {
		l = strings.ToLower(l)
		if len(l) < minKeywordLen {
			return nil // an under-length alternative poisons the whole set
		}
		if _, ok := seen[l]; ok {
			continue
		}
		seen[l] = struct{}{}
		out = append(out, l)
	}
	return out
}

// requiredLiterals returns a necessary literal set for re: every match of re
// contains at least one of the returned strings. nil means "no guarantee".
func requiredLiterals(re *syntax.Regexp) []string {
	switch re.Op {
	case syntax.OpLiteral:
		if s := string(re.Rune); s != "" {
			return []string{s}
		}
		return nil

	case syntax.OpConcat:
		// AND: any conjunct's necessary set is necessary for the whole. Pick the
		// most selective (longest shortest-literal) among the sub-expressions.
		var best []string
		bestScore := 0
		for _, sub := range re.Sub {
			cand := requiredLiterals(sub)
			if len(cand) == 0 {
				continue
			}
			if s := selectivity(cand); s > bestScore {
				best, bestScore = cand, s
			}
		}
		return best

	case syntax.OpAlternate:
		// OR: the set must cover every branch, so union all branches — but only
		// if every branch yields a necessary literal, else there is no guarantee.
		var union []string
		for _, sub := range re.Sub {
			cand := requiredLiterals(sub)
			if len(cand) == 0 {
				return nil
			}
			union = append(union, cand...)
		}
		return union

	case syntax.OpCapture:
		return requiredLiterals(re.Sub[0])

	case syntax.OpPlus:
		// One-or-more: the sub is guaranteed to appear at least once.
		return requiredLiterals(re.Sub[0])

	case syntax.OpRepeat:
		if re.Min >= 1 {
			return requiredLiterals(re.Sub[0])
		}
		return nil

	default:
		// OpStar, OpQuest (optional), OpCharClass, OpAnyChar*, anchors,
		// OpEmptyMatch, OpWordBoundary, etc. contribute no guaranteed literal.
		return nil
	}
}

// selectivity scores a keyword set by the length of its shortest member (the
// weakest link determines how often the prefilter fires).
func selectivity(lits []string) int {
	min := 1 << 30
	for _, l := range lits {
		if len(l) < min {
			min = len(l)
		}
	}
	return min
}
