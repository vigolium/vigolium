package textutil

// Closest is the candidate nearest typed (by Levenshtein distance) within
// SuggestionBudget, "" when none is: the "did you mean" for a mistyped name.
// Ties go to the first candidate, so the hint is stable when candidates come in
// a fixed order.
func Closest(typed string, candidates []string) string {
	best, bestDist := "", -1
	for _, c := range candidates {
		if d := Levenshtein(typed, c); bestDist == -1 || d < bestDist {
			best, bestDist = c, d
		}
	}
	if bestDist >= 0 && bestDist <= SuggestionBudget(typed) {
		return best
	}
	return ""
}

// SuggestionBudget is the largest edit distance still considered a typo of
// typed. One edit for a short name, widening to a third of the name's length for
// longer ones, where the same distance leaves far more of the word intact.
func SuggestionBudget(typed string) int {
	if len(typed) <= 5 {
		return 1
	}
	return len(typed) / 3
}
