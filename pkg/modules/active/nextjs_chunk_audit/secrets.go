package nextjs_chunk_audit

import (
	"bytes"
	"regexp"
	"strings"

	"github.com/vigolium/vigolium/pkg/modules/infra"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
)

type SecretMatch struct {
	Pattern string
	Value   string
	Snippet string
}

type secretRule struct {
	name string
	re   *regexp.Regexp
}

// SYNC WITH pkg/deparos/tag/apikey.go (bodyPatterns). When that list grows,
// mirror the additions here so chunk-scale inline scanning keeps parity.
var secretRules = []secretRule{
	{"aws-access-key-id", regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
	{"google-api-key", regexp.MustCompile(`AIza[0-9A-Za-z_\-]{35}`)},
	{"github-pat", regexp.MustCompile(`gh[pousr]_[A-Za-z0-9_]{36,}`)},
	{"github-fine-grained-pat", regexp.MustCompile(`github_pat_[A-Za-z0-9_]{22,}`)},
	{"stripe-live-secret", regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24,}`)},
	{"stripe-live-publishable", regexp.MustCompile(`pk_live_[0-9a-zA-Z]{24,}`)},
	{"stripe-test-secret", regexp.MustCompile(`sk_test_[0-9a-zA-Z]{24,}`)},
	{"stripe-test-publishable", regexp.MustCompile(`pk_test_[0-9a-zA-Z]{24,}`)},
	{"slack-token", regexp.MustCompile(`xox[baprs]-[0-9A-Za-z\-]{10,}`)},
	{"api-key-assignment", regexp.MustCompile(`(?i)["']?api[-_]?key["']?\s*[:=]\s*["']?[A-Za-z0-9_\-]{20,}["']?`)},
	{"secret-key-assignment", regexp.MustCompile(`(?i)["']?secret[-_]?key["']?\s*[:=]\s*["']?[A-Za-z0-9_\-]{20,}["']?`)},
	{"access-key-assignment", regexp.MustCompile(`(?i)["']?access[-_]?key["']?\s*[:=]\s*["']?[A-Za-z0-9_\-]{20,}["']?`)},
	{"client-secret-assignment", regexp.MustCompile(`(?i)["']?client[-_]?secret["']?\s*[:=]\s*["']?[A-Za-z0-9_\-]{20,}["']?`)},
}

// secretPrefilters is a cheap byte-level gate: if none match, skip the
// full regex sweep. Multi-MB bundles without any secret-shaped tokens
// short-circuit in microseconds.
var secretPrefilters = [][]byte{
	[]byte("AKIA"), []byte("AIza"), []byte("gh"), []byte("github_pat_"),
	[]byte("sk_live_"), []byte("pk_live_"), []byte("sk_test_"), []byte("pk_test_"),
	[]byte("xox"), []byte("ey_key"), []byte("api"), []byte("secret"), []byte("access"), []byte("client"),
}

func FindSecrets(body []byte, limit int) []SecretMatch {
	if len(body) == 0 {
		return nil
	}
	if limit <= 0 {
		limit = 32
	}
	if !hasAnyPrefilter(body) {
		return nil
	}

	var (
		seen = make(map[string]struct{})
		out  []SecretMatch
	)
	for _, rule := range secretRules {
		for _, loc := range rule.re.FindAllIndex(body, -1) {
			if len(out) >= limit {
				return out
			}
			value := normalizedSecretValue(rule.name, string(body[loc[0]:loc[1]]))
			if !credentialValueIsSubstantive(rule.name, value) {
				continue
			}
			key := rule.name + "|" + value
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, SecretMatch{
				Pattern: rule.name,
				Value:   value,
				Snippet: snippetAround(body, loc[0], loc[1]),
			})
		}
	}
	return out
}

func normalizedSecretValue(pattern, value string) string {
	if strings.HasSuffix(pattern, "-assignment") {
		if i := strings.LastIndexAny(value, ":="); i >= 0 {
			value = value[i+1:]
		}
	}
	return strings.TrimSpace(strings.Trim(value, `"'`))
}

func credentialValueIsSubstantive(pattern, value string) bool {
	value = strings.TrimSpace(value)
	if len(value) < 8 || modkit.IsPlaceholderValue(value) {
		return false
	}
	lower := strings.ToLower(value)
	for _, placeholder := range []string{
		"example", "sample", "dummy", "placeholder", "changeme", "change-me",
		"your_", "your-", "redacted", "xxxx", "****", "<", "${",
	} {
		if strings.Contains(lower, placeholder) {
			return false
		}
	}
	if strings.HasSuffix(pattern, "-assignment") && infra.ShannonEntropyBits(value) < 3.2 {
		return false
	}
	return true
}

func hasAnyPrefilter(body []byte) bool {
	for _, p := range secretPrefilters {
		if bytes.Contains(body, p) {
			return true
		}
	}
	return false
}

func snippetAround(body []byte, start, end int) string {
	const ctx = 30
	from := start - ctx
	if from < 0 {
		from = 0
	}
	to := end + ctx
	if to > len(body) {
		to = len(body)
	}
	return string(body[from:to])
}
