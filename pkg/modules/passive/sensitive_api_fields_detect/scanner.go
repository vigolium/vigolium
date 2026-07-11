package sensitive_api_fields_detect

import (
	"encoding/json"
	"regexp"
	"sort"
	"strings"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

var sensitiveFieldLabels = map[string]string{
	"password": "password", "passwd": "passwd",
	"secret": "secret", "apikey": "api_key/apiKey",
	"accesstoken": "access_token/accessToken",
	"privatekey":  "private_key/privateKey",
	"ssn":         "ssn",
	"creditcard":  "credit_card/cardNumber",
	"cardnumber":  "credit_card/cardNumber",
}

var (
	publicAPIIdentifier = regexp.MustCompile(`^(?:AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|pk_(?:live|test)_[0-9A-Za-z]{16,})$`)
	nonDigit            = regexp.MustCompile(`\D`)
)

// Module implements the Sensitive API Fields Detect passive scanner.
type Module struct {
	modkit.BasePassiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new Sensitive API Fields Detect module.
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
		ds: dedup.LazyDiskSet("sensitive_api_fields_detect"),
	}
	m.ModuleTags = ModuleTags
	return m
}

func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	if !ctx.HasResponse() {
		return nil, nil
	}
	// A WAF/CDN edge block's JSON error body is the edge talking, not the
	// application — a "password"/"secret" key in it is not an app field leak.
	if modkit.IsEdgeBlockedResponse(ctx.Response()) {
		return nil, nil
	}

	// Only operate on JSON responses
	ct := strings.ToLower(ctx.Response().Header("Content-Type"))
	if !strings.Contains(ct, "application/json") && !strings.Contains(ct, "+json") {
		return nil, nil
	}

	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	host := urlx.Host
	dedupKey := host + urlx.Path
	var diskSet *dedup.DiskSet
	if scanCtx != nil {
		diskSet = m.ds.Get(scanCtx.DedupMgr())
	}
	if diskSet != nil && diskSet.IsSeen(dedupKey) {
		return nil, nil
	}

	body := ctx.Response().BodyToString()
	if len(body) == 0 {
		return nil, nil
	}

	var document any
	if err := json.Unmarshal([]byte(body), &document); err != nil {
		return nil, nil
	}
	if isSchemaDocument(document) {
		return nil, nil
	}

	foundSet := make(map[string]bool)
	substantiveSet := make(map[string]bool)
	collectSensitiveFields(document, foundSet, substantiveSet)
	found := sortedLabels(foundSet)
	substantive := sortedLabels(substantiveSet)

	if len(found) == 0 {
		return nil, nil
	}

	kind := output.RecordKindObservation
	grade := output.EvidenceGradeObservation
	sev := severity.Info
	name := "Security-Relevant API Field Names"
	desc := "JSON response contains security-relevant field names, but only null, empty, boolean, public-identifier, redacted, or example-like values were observed: " + strings.Join(found, ", ")
	if len(substantive) > 0 {
		kind = output.RecordKindCandidate
		grade = output.EvidenceGradeCandidate
		sev = severity.Low
		name = "Sensitive API Fields Detected"
		desc = "JSON response contains substantive values under sensitive-looking fields: " + strings.Join(substantive, ", ") + ". Sensitivity and cross-role authorization were not validated."
	}

	return []*output.ResultEvent{
		{
			ModuleID:         ModuleID,
			RecordKind:       kind,
			EvidenceGrade:    grade,
			Host:             host,
			URL:              urlx.String(),
			Matched:          urlx.String(),
			Request:          string(ctx.Request().Raw()),
			Response:         string(ctx.Response().Raw()),
			ExtractedResults: found,
			DedupKey:         "sensitive-api-fields|" + host + "|" + urlx.Path + "|" + ctx.Request().IdentityFingerprint(),
			Info: output.Info{
				Name:        name,
				Description: desc,
				// A passive NAME match (the value is never inspected for actual
				// sensitivity) is a review lead, not a confirmed leak — the module
				// text says "each hit needs review" — so it belongs at Low, not
				// Medium. The value gate below drops null/empty/boolean fields.
				Severity:   sev,
				Confidence: severity.Tentative,
				Tags:       []string{"api", "sensitive-data", "information-disclosure", "pii"},
				Reference:  []string{"https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/"},
			},
			Metadata: map[string]any{
				"sensitiveFields":        found,
				"substantiveFields":      substantive,
				"authorization_compared": false,
			},
		},
	}, nil
}

func collectSensitiveFields(node any, found, substantive map[string]bool) {
	switch typed := node.(type) {
	case map[string]any:
		for key, value := range typed {
			normalized := normalizeFieldName(key)
			if label, ok := sensitiveFieldLabels[normalized]; ok {
				found[label] = true
				if isSubstantiveFieldValue(normalized, value) {
					substantive[label] = true
				}
			}
			collectSensitiveFields(value, found, substantive)
		}
	case []any:
		for _, value := range typed {
			collectSensitiveFields(value, found, substantive)
		}
	}
}

func normalizeFieldName(name string) string {
	lower := strings.ToLower(name)
	return strings.NewReplacer("_", "", "-", "", " ", "").Replace(lower)
}

func isSubstantiveFieldValue(field string, value any) bool {
	text, ok := value.(string)
	if !ok {
		return false
	}
	text = strings.TrimSpace(text)
	if modkit.IsPlaceholderValue(text) || looksRedactedExampleOrMasked(text) || publicAPIIdentifier.MatchString(text) {
		return false
	}
	switch field {
	case "password", "passwd":
		return len(text) >= 4
	case "ssn":
		digits := nonDigit.ReplaceAllString(text, "")
		return len(digits) == 9
	case "creditcard", "cardnumber":
		digits := nonDigit.ReplaceAllString(text, "")
		return len(digits) >= 12 && len(digits) <= 19
	default:
		return len(text) >= 8
	}
}

func looksRedactedExampleOrMasked(value string) bool {
	lower := strings.ToLower(value)
	for _, marker := range []string{"example", "placeholder", "changeme", "dummy", "sample", "redacted", "masked", "your_", "your-"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return strings.Trim(value, "*xX._- ") == ""
}

func isSchemaDocument(document any) bool {
	root, ok := document.(map[string]any)
	if !ok {
		return false
	}
	for _, key := range []string{"openapi", "swagger", "$schema"} {
		if _, ok := root[key]; ok {
			return true
		}
	}
	return false
}

func sortedLabels(values map[string]bool) []string {
	labels := make([]string, 0, len(values))
	for label := range values {
		labels = append(labels, label)
	}
	sort.Strings(labels)
	return labels
}
