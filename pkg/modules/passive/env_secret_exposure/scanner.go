package env_secret_exposure

import (
	"fmt"
	"path"
	"regexp"
	"strings"

	urlutil "github.com/projectdiscovery/utils/url"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/vigolium/vigolium/pkg/utils"
)

var (
	// Public framework prefixes deliberately ship values to every browser. A
	// suspicious key name is therefore only useful when the value itself also
	// resembles a credential.
	publicEnvAssignmentPattern = regexp.MustCompile(`(?m)\b((?:NEXT_PUBLIC_|VITE_|REACT_APP_)[A-Z0-9_]*(?:SECRET|KEY|TOKEN|PASSWORD|PRIVATE|CREDENTIAL)[A-Z0-9_]*)\s*[=:]\s*["']([^"'\\\r\n]{8,})["']`)
	dotenvLinePattern          = regexp.MustCompile(`(?m)^\s*([A-Za-z_][A-Za-z0-9_.-]*)\s*=\s*([^\r\n]*)\s*$`)

	knownSecretPatterns = []struct {
		name string
		re   *regexp.Regexp
	}{
		{"GitHub token", regexp.MustCompile(`^(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})$`)},
		{"Stripe secret key", regexp.MustCompile(`^(?:sk|rk)_live_[A-Za-z0-9]{16,}$`)},
		{"OpenAI-style secret key", regexp.MustCompile(`^sk-[A-Za-z0-9_-]{20,}$`)},
		{"Slack credential", regexp.MustCompile(`^xox[baprs]-[A-Za-z0-9-]{20,}$`)},
		{"private key", regexp.MustCompile(`(?i)(?:-----BEGIN|\\n-----BEGIN)[ A-Z0-9_-]*PRIVATE KEY-----`)},
	}

	// These values are identifiers or publishable browser credentials by design.
	// A variable name containing KEY or TOKEN does not turn them into secrets.
	knownPublicValuePatterns = []*regexp.Regexp{
		regexp.MustCompile(`^(?:pk|rk)_(?:live|test)_[A-Za-z0-9]{8,}$`),
		regexp.MustCompile(`^AIza[0-9A-Za-z_-]{20,}$`),
		regexp.MustCompile(`^[0-9]+-[0-9A-Za-z_-]+\.apps\.googleusercontent\.com$`),
		regexp.MustCompile(`^[0-9]+:[0-9]+:web:[0-9a-f]+$`),
	}
)

type credentialAssessment struct {
	label      string
	severity   severity.Severity
	confidence severity.Confidence
	reportable bool
}

// Module implements the environment secret exposure passive scanner.
type Module struct {
	modkit.BasePassiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new Environment Secret Exposure module.
func New() *Module {
	m := &Module{
		BasePassiveModule: modkit.NewBasePassiveModule(
			ModuleID,
			ModuleName,
			ModuleDesc,
			ModuleShort,
			ModuleConfirmation,
			ModuleSeverity,
			ModuleConfidence,
			modkit.ScanScopeRequest,
			modkit.PassiveScanScopeResponse,
		),
		ds: dedup.LazyDiskSet("env_secret_exposure"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// CanProcess accepts text responses and explicit JavaScript, JSON, or .env paths.
func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	if ctx == nil || ctx.Response() == nil || len(ctx.Response().Body()) == 0 {
		return false
	}

	ct := strings.ToLower(ctx.Response().Header("Content-Type"))
	if strings.Contains(ct, "javascript") || strings.Contains(ct, "json") ||
		strings.Contains(ct, "text/html") || strings.Contains(ct, "text/plain") {
		return true
	}

	if u, err := ctx.URL(); err == nil {
		pathLower := strings.ToLower(u.Path)
		return isDotenvPath(pathLower) || strings.HasSuffix(pathLower, ".js") ||
			strings.HasSuffix(pathLower, ".json")
	}

	return false
}

// ScanPerRequest scans a response for credential-shaped values in intentionally
// public environment variables or in a directly served dotenv file. It does not
// treat a sensitive-looking key name as proof that its value is secret.
func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	if !ctx.HasResponse() || modkit.IsEdgeBlockedResponse(ctx.Response()) {
		return nil, nil
	}
	status := ctx.Response().StatusCode()
	if status < 200 || status >= 300 {
		return nil, nil
	}

	urlx, err := ctx.URL()
	if err != nil {
		return nil, nil
	}

	diskSet := m.ds.Get(scanCtx.DedupMgr())
	if diskSet != nil && diskSet.IsSeen(utils.Sha1(urlx.Host)) {
		return nil, nil
	}

	body := ctx.Response().BodyToString()
	ct := strings.ToLower(ctx.Response().Header("Content-Type"))
	var results []*output.ResultEvent

	// Rendered documentation and examples commonly show public-env assignment
	// syntax. Actual bundles remain eligible even when their URL happens to sit
	// below a /docs route.
	if !isRenderedDocumentation(urlx, ct) {
		for _, match := range publicEnvAssignmentPattern.FindAllStringSubmatch(body, -1) {
			key, value := match[1], strings.TrimSpace(match[2])
			assessment := assessCredential(key, value)
			if !assessment.reportable {
				continue
			}
			results = append(results, newCandidate(
				urlx,
				"Public Environment Variable Contains Credential-Shaped Value",
				fmt.Sprintf("%s exposes a value classified as %s. The public framework prefix proves browser exposure, but credential validity still requires provider-side validation.", key, assessment.label),
				[]string{modkit.Truncate(match[0], 120)},
				assessment,
				map[string]any{"variable": key, "source_context": "public-framework-variable"},
			))
		}
	}

	// Generic KEY=VALUE parsing is deliberately limited to a successful response
	// whose URL itself names a dotenv file. Text and HTML pages frequently contain
	// snippets that merely document dotenv syntax.
	if isDotenvPath(urlx.Path) && modkit.ClassifyContentType(ct) != modkit.ContentClassHTML && !modkit.IsJSOrTSContentType(ct) {
		for _, match := range dotenvLinePattern.FindAllStringSubmatch(body, 100) {
			key := strings.TrimSpace(match[1])
			value := trimAssignmentValue(match[2])
			assessment := assessCredential(key, value)
			if !assessment.reportable {
				continue
			}
			results = append(results, newCandidate(
				urlx,
				"Credential-Shaped Value in Served Dotenv File",
				fmt.Sprintf("A successful response for %s contains %s with a value classified as %s. The file exposure is established, but the credential must be validated before it is treated as live.", urlx.Path, key, assessment.label),
				[]string{modkit.Truncate(match[0], 120)},
				assessment,
				map[string]any{"variable": key, "source_context": "dotenv-path"},
			))
		}
	}

	return results, nil
}

func newCandidate(urlx *urlutil.URL, name, description string, extracted []string, assessment credentialAssessment, metadata map[string]any) *output.ResultEvent {
	metadata["credential_class"] = assessment.label
	metadata["validation_required"] = true
	return &output.ResultEvent{
		ModuleID:         ModuleID,
		RecordKind:       output.RecordKindCandidate,
		EvidenceGrade:    output.EvidenceGradeCandidate,
		Host:             urlx.Host,
		URL:              urlx.String(),
		Matched:          urlx.String(),
		ExtractedResults: extracted,
		Info: output.Info{
			Name:        name,
			Description: description,
			Severity:    assessment.severity,
			Confidence:  assessment.confidence,
			Tags:        []string{"secret", "env-exposure", "information-disclosure", "source-analysis"},
		},
		Metadata: metadata,
	}
}

func assessCredential(key, value string) credentialAssessment {
	value = trimAssignmentValue(value)
	if !dotenvValueIsSubstantive(value) || isKnownPublicValue(value) {
		return credentialAssessment{}
	}
	for _, pattern := range knownSecretPatterns {
		if pattern.re.MatchString(value) {
			return credentialAssessment{label: pattern.name, severity: severity.High, confidence: severity.Firm, reportable: true}
		}
	}

	keyLower := strings.ToLower(key)
	if strings.Contains(keyLower, "secret") || strings.Contains(keyLower, "password") ||
		strings.Contains(keyLower, "private") || strings.Contains(keyLower, "credential") ||
		strings.Contains(keyLower, "token") {
		if len(value) >= 16 && infra.ShannonEntropyBits(value) >= 3.2 {
			return credentialAssessment{label: "high-entropy value under a secret-bearing key", severity: severity.Medium, confidence: severity.Tentative, reportable: true}
		}
	}

	// API_KEY and similar names are especially likely to hold intentionally
	// publishable identifiers. Only retain an unrecognized one when it is both
	// long and unusually varied; provider validation is still required.
	if strings.Contains(keyLower, "key") && len(value) >= 24 && infra.ShannonEntropyBits(value) >= 4.0 {
		return credentialAssessment{label: "unrecognized high-entropy key", severity: severity.Medium, confidence: severity.Tentative, reportable: true}
	}
	return credentialAssessment{}
}

func isKnownPublicValue(value string) bool {
	for _, pattern := range knownPublicValuePatterns {
		if pattern.MatchString(value) {
			return true
		}
	}
	return false
}

func isDotenvPath(rawPath string) bool {
	base := strings.ToLower(path.Base(rawPath))
	return base == ".env" || strings.HasPrefix(base, ".env.") || strings.HasSuffix(base, ".env")
}

func isRenderedDocumentation(u *urlutil.URL, contentType string) bool {
	if modkit.ClassifyContentType(contentType) != modkit.ContentClassHTML && !strings.Contains(contentType, "x-component") {
		return false
	}
	for _, segment := range strings.Split(strings.ToLower(u.Path), "/") {
		switch segment {
		case "doc", "docs", "documentation", "reference", "guide", "tutorial", "example", "examples":
			return true
		}
	}
	return false
}

func trimAssignmentValue(value string) string {
	value = strings.TrimSpace(value)
	value = strings.Trim(value, `"'`)
	return strings.TrimSpace(value)
}

// dotenvValueIsSubstantive rejects empty, short, and obvious demonstration
// values before any entropy or provider-specific classification is attempted.
func dotenvValueIsSubstantive(value string) bool {
	value = trimAssignmentValue(value)
	if len(value) < 8 || modkit.IsPlaceholderValue(value) {
		return false
	}
	lower := strings.ToLower(value)
	for _, placeholder := range []string{
		"changeme", "change-me", "your_", "your-", "yourvalue", "placeholder",
		"example", "dummy", "sample", "redacted", "xxxx", "****", "<", "${",
	} {
		if strings.Contains(lower, placeholder) {
			return false
		}
	}
	return true
}
