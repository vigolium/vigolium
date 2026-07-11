package idor_params_detect

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"go.uber.org/zap"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/shared/authzutil"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/vigolium/vigolium/pkg/utils"
)

// Module implements passive IDOR parameter detection.
type Module struct {
	modkit.BasePassiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new IDOR parameter detection passive module.
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
			modkit.PassiveScanScopeBoth,
		),
		ds: dedup.LazyDiskSet("passive_idor_params_detect"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerRequest analyzes request parameters for potential object identifiers
// and response bodies for excessive data exposure.
func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	if utils.IsMediaAndJSURL(urlx.Path) {
		return nil, nil
	}

	pathSegments := strings.Split(urlx.Path, "/")
	normalizedPath := normalizePathPattern(urlx.Path)

	params, err := ctx.Request().Parameters()
	if err != nil {
		return nil, nil
	}

	var diskSet *dedup.DiskSet
	if scanCtx != nil {
		diskSet = m.ds.Get(scanCtx.DedupMgr())
	}

	var results []*output.ResultEvent

	for _, param := range params {
		// A placeholder value ("id=null", "uid=undefined") is not a testable
		// object reference, so it is not an IDOR candidate.
		if modkit.IsPlaceholderValue(param.Value()) {
			continue
		}
		isPath := param.Type() == httpmsg.ParamPathFolder || param.Type() == httpmsg.ParamPathFilename
		classification := authzutil.ClassifyParam(param.Name(), param.Value(), isPath, pathSegments)

		if classification.TotalScore < 3 {
			continue
		}

		// Dedup by host + normalized path + param name + param type
		dedupKey := utils.Sha1(fmt.Sprintf("%s%s%s%s", urlx.Host, normalizedPath, param.Name(), param.Type().String()))
		if diskSet != nil && diskSet.IsSeen(dedupKey) {
			continue
		}

		desc := fmt.Sprintf("Potential object ID parameter: %s=%s (score=%d, name=%s, type=%s, predictability=%s)",
			param.Name(), param.Value(),
			classification.TotalScore,
			classification.NameSignal,
			classification.IDType,
			classification.Predictability,
		)
		if classification.ResourceNoun != "" {
			desc += fmt.Sprintf(", resource=%s", classification.ResourceNoun)
		}

		results = append(results, &output.ResultEvent{
			ModuleID:         ModuleID,
			Host:             urlx.Host,
			URL:              urlx.String(),
			Matched:          urlx.String(),
			Request:          string(ctx.Request().Raw()),
			FuzzingParameter: param.Name(),
			ExtractedResults: []string{fmt.Sprintf("%s=%s", param.Name(), param.Value())},
			RecordKind:       output.RecordKindObservation,
			EvidenceGrade:    output.EvidenceGradeObservation,
			DedupKey:         fmt.Sprintf("idor-candidate|%s|%s|%s|%s", urlx.Host, normalizedPath, param.Name(), param.Type().String()),
			Info: output.Info{
				Name:        "Potential IDOR Parameter",
				Description: desc,
				Severity:    severity.Info,
				Confidence:  severity.Tentative,
				Tags:        []string{"idor", "bola", "access-control", "api-security"},
			},
			Metadata: map[string]any{
				"param_name":             param.Name(),
				"param_value":            param.Value(),
				"param_type":             param.Type().String(),
				"id_type":                classification.IDType.String(),
				"predictability":         classification.Predictability.String(),
				"name_signal":            classification.NameSignal.String(),
				"total_score":            classification.TotalScore,
				"resource_noun":          classification.ResourceNoun,
				"is_path_param":          isPath,
				"authorization_compared": false,
			},
		})
	}

	// Annotate record with semantic tag if IDOR params found
	if len(results) > 0 && scanCtx != nil && scanCtx.RemarksAnnotator != nil && scanCtx.RequestUUIDResolver != nil {
		uuid := scanCtx.RequestUUIDResolver.ResolveRequestUUID(ctx.Request().ID())
		if uuid != "" {
			if err := scanCtx.RemarksAnnotator.AppendRemarks(context.Background(), map[string][]string{uuid: {"idor-candidate"}}); err != nil {
				zap.L().Debug("idor_params_detect: failed to annotate", zap.Error(err))
			}
		}
	}

	// Check for excessive data exposure in JSON responses. Skip WAF/CDN edge
	// blocks: a JSON error body from the edge is not the application leaking data.
	if ctx.HasResponse() && !modkit.IsEdgeBlockedResponse(ctx.Response()) && isJSONResponse(ctx.Response().Header("Content-Type")) {
		body := ctx.Response().BodyToString()
		if len(body) > 0 {
			results = append(results, m.detectExcessiveData(body, urlx.Host, urlx.String(), ctx)...)
		}
	}

	return results, nil
}

// detectExcessiveData parses the JSON response and separates sensitive field
// names from fields carrying substantive values. This avoids treating a JSON
// string containing `"is_admin"`, or a redacted `"password_hash": null`, as
// excessive data exposure.
func (m *Module) detectExcessiveData(body, host, urlStr string, ctx *httpmsg.HttpRequestResponse) []*output.ResultEvent {
	var document any
	if err := json.Unmarshal([]byte(body), &document); err != nil {
		return nil
	}

	seen := make(map[string]bool)
	substantive := make(map[string]bool)
	collectSensitiveJSONFields(document, seen, substantive)
	if len(seen) == 0 {
		return nil
	}

	sensitiveFields := sortedMapKeys(seen)
	substantiveFields := sortedMapKeys(substantive)

	kind := output.RecordKindObservation
	grade := output.EvidenceGradeObservation
	sev := severity.Info
	name := "Security-Relevant API Field Names"
	description := fmt.Sprintf("API response contains security-relevant field names (%s), but their values are empty, false, redacted, example-like, or otherwise non-substantive.", strings.Join(sensitiveFields, ", "))
	if len(substantiveFields) > 0 {
		kind = output.RecordKindCandidate
		grade = output.EvidenceGradeCandidate
		sev = severity.Low
		name = "Potential Excessive Data Exposure"
		description = fmt.Sprintf("API response contains substantive values under security-relevant fields (%s). Cross-role or cross-identity authorization was not compared, so this is a BOPLA review candidate rather than confirmed unauthorized disclosure.", strings.Join(substantiveFields, ", "))
	}

	identity := "anonymous"
	request := ""
	response := ""
	if ctx != nil && ctx.Request() != nil {
		identity = ctx.Request().IdentityFingerprint()
		request = string(ctx.Request().Raw())
	}
	if ctx != nil && ctx.Response() != nil {
		response = string(ctx.Response().Raw())
	}

	return []*output.ResultEvent{
		{
			ModuleID:         ModuleID,
			RecordKind:       kind,
			EvidenceGrade:    grade,
			Host:             host,
			URL:              urlStr,
			Matched:          urlStr,
			Request:          request,
			Response:         response,
			ExtractedResults: sensitiveFields,
			DedupKey:         "excessive-data-candidate|" + host + "|" + urlStr + "|" + identity,
			Info: output.Info{
				Name:        name,
				Description: description,
				Severity:    sev,
				Confidence:  severity.Tentative,
				Tags:        []string{"bopla", "excessive-data", "api-security"},
			},
			Metadata: map[string]any{
				"sensitive_fields":       sensitiveFields,
				"substantive_fields":     substantiveFields,
				"field_count":            len(sensitiveFields),
				"authorization_compared": false,
			},
		},
	}
}

func collectSensitiveJSONFields(node any, seen, substantive map[string]bool) {
	switch typed := node.(type) {
	case map[string]any:
		for key, value := range typed {
			normalized := authzutil.NormalizeName(key)
			if _, ok := authzutil.SensitiveResponseFields[normalized]; ok {
				seen[normalized] = true
				if isSubstantiveSensitiveFieldValue(normalized, value) {
					substantive[normalized] = true
				}
			}
			collectSensitiveJSONFields(value, seen, substantive)
		}
	case []any:
		for _, value := range typed {
			collectSensitiveJSONFields(value, seen, substantive)
		}
	}
}

func isSubstantiveSensitiveFieldValue(field string, value any) bool {
	if value == nil {
		return false
	}
	switch typed := value.(type) {
	case bool:
		return typed // false privilege flags are routine serialization, not exposure evidence
	case float64:
		return field == "ssn" || field == "social_security" || field == "credit_card" || field == "card_number" || field == "cvv"
	case string:
		trimmed := strings.TrimSpace(typed)
		if modkit.IsPlaceholderValue(trimmed) || looksRedactedOrExample(trimmed) {
			return false
		}
		if field == "access_level" || field == "permissions" {
			return trimmed != ""
		}
		return len(trimmed) >= 8
	case []any:
		return len(typed) > 0
	case map[string]any:
		return len(typed) > 0
	}
	return false
}

func looksRedactedOrExample(value string) bool {
	lower := strings.ToLower(value)
	for _, marker := range []string{"example", "placeholder", "changeme", "dummy", "sample", "redacted", "masked", "your_", "your-"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return strings.Trim(value, "*xX._- ") == ""
}

func sortedMapKeys(values map[string]bool) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

// normalizePathPattern replaces ID-like segments with {id} for dedup grouping.
// E.g., /api/users/123/orders/456 → /api/users/{id}/orders/{id}
func normalizePathPattern(path string) string {
	segments := strings.Split(path, "/")
	changed := false
	for i, seg := range segments {
		if seg == "" {
			continue
		}
		if authzutil.SequentialIntPattern.MatchString(seg) ||
			authzutil.UUIDv4Pattern.MatchString(seg) ||
			authzutil.UUIDv1Pattern.MatchString(seg) ||
			authzutil.HexPattern.MatchString(seg) ||
			authzutil.StructuredCodePattern.MatchString(seg) {
			segments[i] = "{id}"
			changed = true
		}
	}
	if !changed {
		return path
	}
	return strings.Join(segments, "/")
}

// isJSONResponse checks if the Content-Type indicates a JSON response.
func isJSONResponse(contentType string) bool {
	if contentType == "" {
		return false
	}
	lower := strings.ToLower(contentType)
	return strings.Contains(lower, "application/json") || strings.Contains(lower, "+json")
}
