package sensitive_url_params

import (
	"regexp"
	"strings"
	"unicode"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/vigolium/vigolium/pkg/utils"
)

var (
	publicIdentifierValue = regexp.MustCompile(`^(?:AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|pk_(?:live|test)_[0-9A-Za-z]{16,})$`)
	maskOnlyValue         = regexp.MustCompile(`^[*xX._-]{4,}$`)
)

var exactSensitiveParamNames = map[string]bool{
	"password": true, "passwd": true, "pwd": true,
	"secret": true, "token": true, "api_key": true, "apikey": true,
	"access_token": true, "auth_token": true, "session_id": true,
	"private_key": true, "credit_card": true, "ssn": true, "cvv": true, "pin": true,
}

var lowSignalTokenNames = map[string]bool{
	"page_token": true, "pagination_token": true, "continuation_token": true,
	"next_page_token": true, "cursor_token": true, "csrf_token": true, "xsrf_token": true,
}

// Module implements the Sensitive URL Params passive scanner.
type Module struct {
	modkit.BasePassiveModule
	rhm dedup.Lazy[dedup.RequestHashManager]
}

// New creates a new Sensitive URL Params module.
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
			modkit.PassiveScanScopeRequest,
		),
		rhm: dedup.LazyDefaultRHM("passive_sensitive_url_params"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerRequest analyzes URL query parameters for sensitive data.
func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	if utils.IsMediaAndJSURL(urlx.Path) {
		return nil, nil
	}

	var results []*output.ResultEvent

	var rhm *dedup.RequestHashManager
	if scanCtx != nil {
		rhm = m.rhm.Get(scanCtx.DedupMgr())
	}

	urlx.Params.Iterate(func(key string, value []string) bool {
		isSensitive, lowSignal := classifySensitiveParamName(key)
		if isSensitive {
			joined := strings.Join(value, ",")
			// Skip empty / JS-placeholder values ("token=null", "secret="): nothing
			// sensitive is disclosed, so flagging the bare parameter name is noise.
			if modkit.IsPlaceholderValue(joined) {
				return true
			}
			if rhm == nil || rhm.ShouldCheck3(urlx, ctx.Request().Method(), ctx.Request().BodyToString(), key, "", "inURL") {
				kind := output.RecordKindCandidate
				grade := output.EvidenceGradeCandidate
				sev := severity.Medium
				conf := severity.Firm
				reason := "A substantive value is carried in a credential-like URL parameter. URL placement is confirmed, but credential validity and replay impact were not tested."
				if lowSignal || publicIdentifierValue.MatchString(strings.TrimSpace(joined)) || looksMaskedOrExample(joined) {
					kind = output.RecordKindObservation
					grade = output.EvidenceGradeObservation
					sev = severity.Info
					conf = severity.Tentative
					reason = "A security-relevant parameter name is present in the URL, but the name or value is commonly public, pagination-related, masked, or example data."
				}
				// Mask the value for reporting
				maskedValue := maskValue(joined)
				results = append(results, &output.ResultEvent{
					ModuleID:         ModuleID,
					RecordKind:       kind,
					EvidenceGrade:    grade,
					Host:             urlx.Host,
					URL:              urlx.String(),
					Matched:          urlx.String(),
					FuzzingParameter: key,
					Request:          string(ctx.Request().Raw()),
					ExtractedResults: []string{key + "=" + maskedValue},
					Info: output.Info{
						Name:        "Security-Relevant Value in URL Parameter",
						Description: reason + " Parameter: " + key + ".",
						Severity:    sev,
						Confidence:  conf,
						Tags:        []string{"passive", "url", "credentials", "information-disclosure"},
					},
					Metadata: map[string]any{
						"parameter_name":       key,
						"low_signal_name":      lowSignal,
						"public_identifier":    publicIdentifierValue.MatchString(strings.TrimSpace(joined)),
						"credential_validated": false,
					},
				})
			}
		}
		return true
	})

	return results, nil
}

func classifySensitiveParamName(name string) (sensitive bool, lowSignal bool) {
	normalized := normalizeParamName(name)
	if lowSignalTokenNames[normalized] {
		return true, true
	}
	if exactSensitiveParamNames[normalized] {
		return true, false
	}
	for candidate := range exactSensitiveParamNames {
		if strings.HasSuffix(normalized, "_"+candidate) {
			return true, false
		}
	}
	// Token is useful as a boundary-delimited suffix (reset_token,
	// invite_token), but not as an arbitrary substring (tokenize, tokenizer).
	if strings.HasSuffix(normalized, "_token") {
		return true, false
	}
	return false, false
}

func normalizeParamName(name string) string {
	var b strings.Builder
	previousSeparator := false
	for i, r := range strings.TrimSpace(name) {
		if unicode.IsUpper(r) && i > 0 && !previousSeparator {
			b.WriteByte('_')
		}
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(unicode.ToLower(r))
			previousSeparator = false
			continue
		}
		if !previousSeparator && b.Len() > 0 {
			b.WriteByte('_')
			previousSeparator = true
		}
	}
	return strings.Trim(b.String(), "_")
}

func looksMaskedOrExample(value string) bool {
	trimmed := strings.TrimSpace(value)
	lower := strings.ToLower(trimmed)
	if maskOnlyValue.MatchString(trimmed) {
		return true
	}
	for _, marker := range []string{"example", "placeholder", "changeme", "dummy", "sample", "redacted", "your_", "your-", "<secret", "${", "{{"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

// maskValue masks sensitive values for safe reporting.
func maskValue(v string) string {
	if len(v) <= 4 {
		return "****"
	}
	return v[:2] + "****" + v[len(v)-2:]
}
