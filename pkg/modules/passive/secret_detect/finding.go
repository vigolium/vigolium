package secret_detect

import (
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/secretscan"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// EvidenceContext carries the per-response context GradeMatch needs to grade a
// secret match and rebuild its evidence. It is identical for every match in one
// response, so callers build it once and reuse it across that response's matches.
type EvidenceContext struct {
	Body         []byte
	Host         string
	URL          string
	Request      string
	RespHead     string
	StatusCode   int
	ContentType  string
	HeaderValues string
}

// GradeMatch applies the structural false-positive guard, severity grading, and
// evidence reconstruction to one native secret match, returning the built
// finding — or (nil, false) if the match is a structural false positive to drop.
// Callers own deduplication and any source-specific fields (ModuleType,
// FindingSource, extra tags). Sharing this keeps the passive module and the
// known-issue-scan batch from drifting in the guard, the 9-way severity call, or
// evidence rendering (they already had — this is the single source of truth).
func GradeMatch(mt secretscan.Match, ev EvidenceContext) (*output.ResultEvent, bool) {
	// Drop matches that are structural false positives — an encoded-binary blob,
	// a JS unicode-escape source artifact, or a build-tool content-hash manifest
	// entry — rather than real credentials (see IsNonSecretMatch). The detector's
	// byte offsets pin each guard to the occurrence that actually matched, so a
	// value seen both inside a blob and in a real assignment is judged by the
	// right one.
	if IsNonSecretMatch(ev.Body, mt.Secret, mt.Start, mt.End) {
		return nil, false
	}

	// A match from one of the curated high-confidence kingfisher rules is the
	// trusted tier; a generic, family-less rule is the low-signal Suspect tier;
	// everything else is a named provider family (High baseline).
	trusted := mt.Source == "kingfisher" && mt.Confidence == "high"
	generic := IsGenericSecretRule(mt.RuleID, mt.RuleName)

	// Untrusted-tier matches: drop values whose shape alone marks them as
	// non-credentials — a mis-attributed reCAPTCHA site key or a code/markup
	// fragment (see IsValueShapeNoise). The high-confidence rules are anchored
	// tightly enough to trust their captures verbatim, so they skip this guard.
	if !trusted && IsValueShapeNoise(mt.RuleName, mt.Secret) {
		return nil, false
	}

	// The native detector performs no live verification, so validated is always
	// false; the remaining signals downgrade low-value reflections, docs/demo
	// samples, public identifiers, and undecodable JWTs (see SecretFindingSeverity).
	sev, conf := SecretFindingSeverity(
		trusted,
		generic,
		false,
		IsRedirectStatus(ev.StatusCode),
		SnippetInHeaderValues(mt.Secret, ev.HeaderValues),
		SnippetReflectedFromRequest(mt.Secret, ev.URL, ev.Request),
		IsDocDemoSecretContext(ev.URL, ev.ContentType),
		LowValueJWT(mt.Secret),
		IsReCaptchaSiteKey(mt.RuleName),
		IsGoogleAPIKey(mt.RuleName, mt.Secret),
		IsGoogleOAuthClientID(mt.Secret),
	)

	// Reconstruct the matched response (head + full-or-windowed body) so the
	// finding shows the actual leak in context; the evidence window is anchored on
	// the detector's byte offsets (with the match line, derived from the same
	// offset, as a fallback) so it centers on the exact occurrence that fired.
	response := BuildEvidenceResponse(ev.RespHead, ev.Body, mt.Secret, mt.Start, mt.End, MatchLine(ev.Body, mt.Start))
	event := NewSecretFinding(mt.RuleID, mt.RuleName, mt.Secret, mt.Pattern, sev, conf, ev.Host, ev.URL, ev.Request, response)
	return event, true
}

// SecretDedupKey builds the identity used to collapse duplicate secret findings:
// the same secret value (snippet), from the same rule, on the same URL is the
// same leak no matter how many times it is re-observed. The same page is fetched
// across discovery, spidering, targeted re-spider, and the dynamic-assessment
// baseline, so the passive module buffers — and the detector re-matches — it once
// per pass, yielding several findings that differ only by a few dynamic bytes in
// the body. Deduping on (host, url, rule_id, snippet) keeps one finding per unique
// secret per URL, which stops near-identical request/response copies from piling
// up as redundant Additional Evidence when the storage layer later merges them.
// The same secret on a *different* URL keeps a distinct key (and is grouped by
// value later if warranted).
func SecretDedupKey(host, url, ruleID, snippet string) string {
	return host + "\x00" + url + "\x00" + ruleID + "\x00" + snippet
}

// NewSecretFinding builds the ResultEvent shared by both secret-finding emission
// paths — the passive module and the known-issue-scan batch — so the two can't
// drift in title, tags, evidence, or metadata (they already did once: one path
// titled findings by rule ID, the other by rule name). Callers set the
// source-specific fields (ModuleID, ModuleType, FindingSource, ModuleShort, and
// any extra tags) on the returned event.
//
// Secret verification is not performed (the native detector has no live-check),
// so metadata "validated" is always false.
func NewSecretFinding(ruleID, ruleName, snippet, pattern string, sev severity.Severity, conf severity.Confidence, host, url, request, response string) *output.ResultEvent {
	tags := []string{"secret", "credential", "exposure"}
	// Mark generic, family-less matches so the storage grouping pass folds them
	// into the per-host "Low-confidence secret-shaped matches" bundle. A named
	// provider family (Google, Storyblok, …) is left untagged and stays its own
	// finding even when severity-downgraded to Suspect (see output.SuspectBundleTag).
	if IsGenericSecretRule(ruleID, ruleName) {
		tags = append(tags, output.SuspectBundleTag)
	}
	return &output.ResultEvent{
		Info: output.Info{
			Name:        ruleName,
			Description: secretFindingDescription(ruleName, snippet, pattern),
			Severity:    sev,
			Confidence:  conf,
			Tags:        tags,
		},
		Host:             host,
		URL:              url,
		Matched:          url,
		ExtractedResults: []string{snippet},
		Request:          request,
		Response:         response,
		Metadata: map[string]any{
			"rule_id":   ruleID,
			"rule_name": ruleName,
			"validated": false,
			// Short, normalised classification of the secret (e.g. "JWT", "Google
			// API key"). The console renders it as a leading bracket before the
			// matched value; it also rides along in the jsonl/DB `meta` object for
			// triage.
			"pattern": PatternLabel(ruleName, snippet),
		},
	}
}
