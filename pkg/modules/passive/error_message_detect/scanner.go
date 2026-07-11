package error_message_detect

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/vigolium/vigolium/pkg/utils"
)

type errorSignature struct {
	name          string
	severity      severity.Severity
	confidence    severity.Confidence
	priority      int
	primary       []*regexp.Regexp
	corroborating []*regexp.Regexp
}

var errorSignatures = []errorSignature{
	{
		name:       "SQL Error",
		severity:   severity.Low,
		confidence: severity.Firm,
		priority:   5,
		primary: []*regexp.Regexp{
			regexp.MustCompile(`(?i)You have an error in your SQL syntax`),
			regexp.MustCompile(`(?i)\bSQLSTATE(?:\[[0-9A-Z]+\])?`),
			regexp.MustCompile(`(?i)\bORA-[0-9]{5}\b`),
			regexp.MustCompile(`(?i)(?:PSQLException|MySqlClient\.|Npgsql\.|SQLiteException|DB2 SQL error|Dynamic SQL Error)`),
			regexp.MustCompile(`(?i)(?:Unclosed quotation mark|Unknown column|relation ["'][^"']+["'] does not exist)`),
		},
		corroborating: []*regexp.Regexp{
			regexp.MustCompile(`(?i)\b(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE|JOIN|query|column|table|relation)\b`),
			regexp.MustCompile(`(?i)\b(?:syntax|database|driver|statement|constraint)\b`),
			regexp.MustCompile(`(?i)(?:\.php on line [0-9]+|\.(?:java|cs|rb|py):?[0-9]+)`),
		},
	},
	{
		name:       "Java Error",
		severity:   severity.Info,
		confidence: severity.Firm,
		priority:   4,
		primary: []*regexp.Regexp{
			regexp.MustCompile(`\bjava\.(?:lang|io|util)\.[A-Za-z0-9_$]*(?:Exception|Error)\b`),
			regexp.MustCompile(`\borg\.[A-Za-z0-9_.$]+\.(?:Exception|Error)\b`),
		},
		corroborating: []*regexp.Regexp{
			regexp.MustCompile(`\bat\s+[A-Za-z0-9_.$]+\([^\n)]*\.java:[0-9]+\)`),
			regexp.MustCompile(`\.java:[0-9]+`),
			regexp.MustCompile(`(?i)(?:Caused by:|nested exception|Unknown Source)`),
		},
	},
	{
		name:       "ASP.NET Error",
		severity:   severity.Info,
		confidence: severity.Firm,
		priority:   4,
		primary: []*regexp.Regexp{
			regexp.MustCompile(`(?i)Server Error in (?:'[^']*'|Application)`),
			regexp.MustCompile(`(?i)(?:System\.[A-Za-z0-9_.]+Exception|Microsoft OLE DB Provider)`),
		},
		corroborating: []*regexp.Regexp{
			regexp.MustCompile(`(?i)End of inner exception stack trace`),
			regexp.MustCompile(`(?i)in [A-Za-z]:\\[^\r\n]+\.cs:line [0-9]+`),
			regexp.MustCompile(`(?i)at [A-Za-z0-9_.]+\([^\r\n]*\)`),
		},
	},
	{
		name:       "Debug Page",
		severity:   severity.Low,
		confidence: severity.Firm,
		priority:   3,
		primary: []*regexp.Regexp{
			regexp.MustCompile(`(?i)\bDEBUG\s*[=:]\s*True\b`),
			regexp.MustCompile(`(?i)(?:Application-Trace|Routing Error|phpinfo\s*\(|Microsoft \.NET Framework)`),
			regexp.MustCompile(`(?i)Traceback \(most recent call last\):`),
		},
		corroborating: []*regexp.Regexp{
			regexp.MustCompile(`(?i)(?:stack trace:|Caused by:|Exception of type|Fatal error:)`),
			regexp.MustCompile(`(?i)File ["'][^"']+["'], line [0-9]+`),
			regexp.MustCompile(`(?i)(?:\.php on line [0-9]+|/[A-Za-z0-9_./-]+\.(?:py|rb|go|js|ts):[0-9]+)`),
		},
	},
	{
		name:       "Apache Error",
		severity:   severity.Info,
		confidence: severity.Firm,
		priority:   2,
		primary: []*regexp.Regexp{
			regexp.MustCompile(`\bAH[0-9]{5}:?\b`),
		},
		corroborating: []*regexp.Regexp{
			regexp.MustCompile(`(?i)\b(?:Apache|request|server|configuration|module|limit|proxy)\b`),
			regexp.MustCompile(`\bmod_[A-Za-z0-9_]+:`),
		},
	},
	{
		name:       "Runtime Error",
		severity:   severity.Info,
		confidence: severity.Firm,
		priority:   1,
		primary: []*regexp.Regexp{
			regexp.MustCompile(`\b(?:TypeError|ReferenceError|NameError|ImportError|IndentationError|UnhandledPromiseRejectionWarning):`),
			regexp.MustCompile(`(?i)\bFatal error:`),
		},
		corroborating: []*regexp.Regexp{
			regexp.MustCompile(`(?m)\bat\s+[^\r\n]+\.(?:js|ts|mjs|cjs):[0-9]+(?::[0-9]+)?`),
			regexp.MustCompile(`(?i)File ["'][^"']+["'], line [0-9]+`),
			regexp.MustCompile(`(?i)\.(?:php|rb|groovy|scala)\b[^\r\n]*\bline?\s*[0-9]+`),
		},
	},
}

var structuredStackTracePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?s)Traceback \(most recent call last\):.*File "[^"]+", line [0-9]+`),
	regexp.MustCompile(`(?m)(?:^\s*at\s+[A-Za-z0-9_.$<>]+\([^\n)]*\.(?:java|js|ts|cs):[0-9]+[^\n]*\)\s*$\n?){2,}`),
	regexp.MustCompile(`(?m)(?:^\s*#\d+\s+/[^\n]+\.php\([0-9]+\):[^\n]+$\n?){2,}`),
	regexp.MustCompile("(?m)(?:^/[^\\n]+\\.rb:[0-9]+:in `[^']+'$\\n?){2,}"),
}

type signatureMatch struct {
	signature errorSignature
	evidence  []string
	score     int
}

// Module implements the Error Message Detect passive scanner.
type Module struct {
	modkit.BasePassiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

func New() *Module {
	m := &Module{
		BasePassiveModule: modkit.NewBasePassiveModule(
			ModuleID, ModuleName, ModuleDesc, ModuleShort, ModuleConfirmation,
			ModuleSeverity, ModuleConfidence,
			modkit.ScanScopeRequest, modkit.PassiveScanScopeResponse,
		),
		ds: dedup.LazyDiskSet("passive_error_message_detect"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerRequest requires a semantic error response plus independent error
// anchors. Single tokens such as TypeError:, ReferenceError:, Caused by:, or
// "on line N" can occur in ordinary page text and never trigger alone.
func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}
	if utils.IsMediaAndJSURL(urlx.Path) || ctx.Response() == nil || modkit.IsStaticAssetContentType(ctx.Response().Header("Content-Type")) || modkit.IsEdgeBlockedResponse(ctx.Response()) {
		return nil, nil
	}
	body := ctx.Response().BodyToString()
	if body == "" || looksLikeStructuredStackTrace(body) {
		// The verbose_error_stacktrace module owns structured multi-frame traces,
		// preventing duplicate results from the two module families.
		return nil, nil
	}

	status := ctx.Response().StatusCode()
	isErrorStatus := status >= 400 && status <= 599
	best := bestSignatureMatch(body, isErrorStatus)
	if best == nil {
		return nil, nil
	}

	diskSet := m.ds.Get(scanCtx.DedupMgr())
	dedupKey := utils.Sha1(fmt.Sprintf("%s%s", urlx.Host, urlx.Path))
	if diskSet != nil && diskSet.IsSeen(dedupKey) {
		return nil, nil
	}

	extracted := []string{fmt.Sprintf("Category: %s", best.signature.name), fmt.Sprintf("HTTP status: %d", status)}
	for _, evidence := range best.evidence {
		extracted = append(extracted, "Matched: "+evidence)
	}

	return []*output.ResultEvent{{
		ModuleID:         ModuleID,
		RecordKind:       output.RecordKindObservation,
		EvidenceGrade:    output.EvidenceGradeObservation,
		Host:             urlx.Host,
		URL:              urlx.String(),
		Matched:          urlx.String(),
		Request:          string(ctx.Request().Raw()),
		ExtractedResults: extracted,
		Info: output.Info{
			Name:        best.signature.name + " in Error Response",
			Description: fmt.Sprintf("The response contains multiple independent %s anchors in an error context. This is an information-disclosure observation; it does not by itself establish an underlying injection vulnerability.", strings.ToLower(best.signature.name)),
			Severity:    best.signature.severity,
			Confidence:  best.signature.confidence,
			Tags:        []string{"passive", "error", "information-disclosure", strings.ToLower(strings.ReplaceAll(best.signature.name, " ", "-"))},
		},
		Metadata: map[string]any{"status_code": status, "anchor_count": len(best.evidence), "structured_stacktrace": false},
	}}, nil
}

func bestSignatureMatch(body string, isErrorStatus bool) *signatureMatch {
	var best *signatureMatch
	for _, signature := range errorSignatures {
		primary := uniquePatternMatches(signature.primary, body)
		corroborating := uniquePatternMatches(signature.corroborating, body)
		if len(primary) == 0 || len(corroborating) == 0 {
			continue
		}
		evidence := append(primary, corroborating...)
		// A successful response needs at least three distinct anchors to overcome
		// the likelihood of documentation, examples, or ordinary application copy.
		if !isErrorStatus && len(evidence) < 3 {
			continue
		}
		candidate := &signatureMatch{signature: signature, evidence: evidence, score: signature.priority*100 + len(evidence)}
		if best == nil || candidate.score > best.score {
			best = candidate
		}
	}
	return best
}

func uniquePatternMatches(patterns []*regexp.Regexp, body string) []string {
	seen := make(map[string]bool)
	var matches []string
	for _, pattern := range patterns {
		match := strings.TrimSpace(pattern.FindString(body))
		if match == "" {
			continue
		}
		match = truncate(match, 140)
		key := strings.ToLower(match)
		if seen[key] {
			continue
		}
		seen[key] = true
		matches = append(matches, match)
	}
	return matches
}

func looksLikeStructuredStackTrace(body string) bool {
	for _, pattern := range structuredStackTracePatterns {
		if pattern.MatchString(body) {
			return true
		}
	}
	return false
}

func truncate(value string, maxLen int) string {
	if len(value) <= maxLen {
		return value
	}
	return value[:maxLen] + "..."
}
