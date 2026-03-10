package sensitive_api_fields_detect

import (
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/pkg/errors"
)

// sensitiveFields are JSON field name patterns to detect.
// Each entry is checked as a quoted key in the response body.
var sensitiveFields = []struct {
	patterns []string // patterns to match (with quotes)
	label    string   // human-readable label
}{
	{
		patterns: []string{`"password":`, `"password" :`},
		label:    "password",
	},
	{
		patterns: []string{`"passwd":`, `"passwd" :`},
		label:    "passwd",
	},
	{
		patterns: []string{`"secret":`, `"secret" :`},
		label:    "secret",
	},
	{
		patterns: []string{`"api_key":`, `"api_key" :`, `"apiKey":`, `"apiKey" :`, `"api-key":`, `"api-key" :`},
		label:    "api_key/apiKey",
	},
	{
		patterns: []string{`"access_token":`, `"access_token" :`, `"accessToken":`, `"accessToken" :`},
		label:    "access_token/accessToken",
	},
	{
		patterns: []string{`"private_key":`, `"private_key" :`, `"privateKey":`, `"privateKey" :`},
		label:    "private_key/privateKey",
	},
	{
		patterns: []string{`"ssn":`, `"ssn" :`},
		label:    "ssn",
	},
	{
		patterns: []string{`"credit_card":`, `"credit_card" :`, `"creditCard":`, `"creditCard" :`, `"card_number":`, `"card_number" :`, `"cardNumber":`, `"cardNumber" :`},
		label:    "credit_card/cardNumber",
	},
}

// antiPatterns indicate the response is a schema or documentation page.
var antiPatterns = []string{
	`"$ref"`,
	`"swagger"`,
	`"openapi"`,
}

// exclusionSuffixes for "password" field to skip non-sensitive contexts
var passwordExclusions = []string{
	`"password_reset"`,
	`"password_policy"`,
}

// secretExclusions for "secret" field to skip non-sensitive contexts
var secretExclusions = []string{
	`"secret_question"`,
}

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

	// Only operate on JSON responses
	ct := strings.ToLower(ctx.Response().Header("Content-Type"))
	if !strings.Contains(ct, "application/json") {
		return nil, nil
	}

	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	host := urlx.Host
	dedupKey := host + urlx.Path
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	if diskSet != nil && diskSet.IsSeen(dedupKey) {
		return nil, nil
	}

	body := ctx.Response().BodyToString()
	if len(body) == 0 {
		return nil, nil
	}

	bodyLower := strings.ToLower(body)

	// Check anti-patterns: skip if this is a schema/doc response
	for _, ap := range antiPatterns {
		if strings.Contains(bodyLower, ap) {
			return nil, nil
		}
	}

	// Check for sensitive fields
	var found []string
	for _, sf := range sensitiveFields {
		matched := false
		for _, pat := range sf.patterns {
			if strings.Contains(bodyLower, strings.ToLower(pat)) {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}

		// Apply exclusions for specific fields
		if sf.label == "password" {
			excluded := false
			for _, ex := range passwordExclusions {
				if strings.Contains(bodyLower, strings.ToLower(ex)) {
					excluded = true
					break
				}
			}
			if excluded {
				continue
			}
		}
		if sf.label == "secret" {
			excluded := false
			for _, ex := range secretExclusions {
				if strings.Contains(bodyLower, strings.ToLower(ex)) {
					excluded = true
					break
				}
			}
			if excluded {
				continue
			}
		}

		found = append(found, sf.label)
	}

	if len(found) == 0 {
		return nil, nil
	}

	desc := "JSON API response contains sensitive field names: " + strings.Join(found, ", ")

	return []*output.ResultEvent{
		{
			ModuleID:         ModuleID,
			Host:             host,
			URL:              urlx.String(),
			Matched:          urlx.String(),
			ExtractedResults: found,
			Info: output.Info{
				Name:        "Sensitive API Fields Detected",
				Description: desc,
				Severity:    severity.Medium,
				Confidence:  severity.Tentative,
				Tags:        []string{"api", "sensitive-data", "information-disclosure", "pii"},
				Reference:   []string{"https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/"},
			},
			Metadata: map[string]any{
				"sensitiveFields": found,
			},
		},
	}, nil
}
