package password_autocomplete_detect

import (
	"fmt"
	"strings"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/utils"
	"golang.org/x/net/html"
)

const maxExamples = 8

// Module implements the Password Autocomplete Detect passive scanner.
type Module struct {
	modkit.BasePassiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new Password Autocomplete Detect module.
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
		ds: dedup.LazyDiskSet("passive_password_autocomplete_detect"),
	}
	m.ModuleTags = ModuleTags
	return m
}

func (m *Module) RequiredContentClasses() []string { return []string{"html"} }

// ScanPerRequest records a markup-quality observation when a likely account
// password input lacks the semantic current-password/new-password token. It no
// longer treats autocomplete=off as the secure state: disabling autofill is not
// an authentication control, and user agents may override it for credentials.
func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}
	if utils.IsMediaAndJSURL(urlx.Path) || ctx.Response() == nil {
		return nil, nil
	}
	if !strings.Contains(strings.ToLower(ctx.Response().Header("Content-Type")), "text/html") {
		return nil, nil
	}

	// The shared, memoised parse (ECON-14): the other HTML passives reuse it.
	doc, err := ctx.Response().HTMLDocument()
	if err != nil || doc == nil {
		return nil, nil
	}
	observations := passwordFieldsWithoutSemanticAutocomplete(doc)
	if len(observations) == 0 {
		return nil, nil
	}

	diskSet := m.ds.Get(scanCtx.DedupMgr())
	dedupKey := utils.Sha1(urlx.Host + urlx.Path)
	if diskSet != nil && diskSet.IsSeen(dedupKey) {
		return nil, nil
	}

	return []*output.ResultEvent{{
		ModuleID:         ModuleID,
		RecordKind:       output.RecordKindObservation,
		EvidenceGrade:    output.EvidenceGradeObservation,
		Host:             urlx.Host,
		URL:              urlx.String(),
		Request:          string(ctx.Request().Raw()),
		ExtractedResults: observations,
		Info: output.Info{
			Name:        "Password Field Lacks Semantic Autocomplete Hint",
			Description: "A likely account-password input does not declare autocomplete=\"current-password\" or autocomplete=\"new-password\". This is an informational password-manager interoperability observation, not proof that credentials are insecurely stored. autocomplete=\"off\" is not a security requirement and is not treated as protection.",
			Severity:    ModuleSeverity,
			Confidence:  ModuleConfidence,
			Tags:        ModuleTags,
		},
		Metadata: map[string]any{
			"recommended_tokens": []string{"current-password", "new-password"},
			"security_impact":    "not established",
			"field_count":        len(observations),
		},
	}}, nil
}

// passwordFieldsWithoutSemanticAutocomplete walks the (shared, read-only)
// document for account-password inputs lacking a semantic autocomplete token.
func passwordFieldsWithoutSemanticAutocomplete(doc *html.Node) []string {
	var observations []string

	var walk func(*html.Node) bool
	walk = func(node *html.Node) bool {
		if node.Type == html.ElementNode && node.Data == "input" {
			if obs, ok := passwordFieldObservation(node); ok {
				observations = append(observations, obs)
				if len(observations) == maxExamples {
					return false
				}
			}
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			if !walk(child) {
				return false
			}
		}
		return true
	}
	walk(doc)
	return observations
}

// passwordFieldObservation describes one enabled, editable password input
// without a semantic autocomplete token, or reports false.
func passwordFieldObservation(node *html.Node) (string, bool) {
	attrs := autocompleteAttributeMap(node.Attr)
	if !strings.EqualFold(strings.TrimSpace(attrs["type"]), "password") || attrs["disabled"] != "" || attrs["readonly"] != "" {
		return "", false
	}

	autocomplete := autocompleteTokenSet(attrs["autocomplete"])
	if autocomplete["current-password"] || autocomplete["new-password"] || autocomplete["one-time-code"] || autocomplete["cc-csc"] {
		return "", false
	}
	if likelyNonPasswordSecretField(attrs) {
		return "", false
	}

	name := firstNonEmpty(attrs["name"], attrs["id"], "(unnamed)")
	hint := strings.TrimSpace(attrs["autocomplete"])
	if hint == "" {
		hint = "(missing)"
	}
	return fmt.Sprintf("field=%s autocomplete=%s", name, hint), true
}

func autocompleteAttributeMap(attrs []html.Attribute) map[string]string {
	result := make(map[string]string, len(attrs))
	for _, attr := range attrs {
		key := strings.ToLower(attr.Key)
		// Boolean attributes have an empty value, so store a sentinel for presence.
		if (key == "disabled" || key == "readonly") && attr.Val == "" {
			result[key] = "present"
		} else {
			result[key] = attr.Val
		}
	}
	return result
}

func autocompleteTokenSet(raw string) map[string]bool {
	result := make(map[string]bool)
	for _, token := range strings.Fields(strings.ToLower(raw)) {
		result[token] = true
	}
	return result
}

func likelyNonPasswordSecretField(attrs map[string]string) bool {
	identity := strings.ToLower(attrs["name"] + " " + attrs["id"])
	for _, marker := range []string{"otp", "one-time", "one_time", "pin", "cvv", "cvc", "security-code", "security_code"} {
		if strings.Contains(identity, marker) {
			return true
		}
	}
	return false
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
