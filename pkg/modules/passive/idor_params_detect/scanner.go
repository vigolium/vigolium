package idor_params_detect

import (
	"context"
	"fmt"
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

	diskSet := m.ds.Get(scanCtx.DedupMgr())

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
			Info: output.Info{
				Name:        "Potential IDOR Parameter",
				Description: desc,
				Severity:    severity.Info,
				Confidence:  severity.Tentative,
				Tags:        []string{"idor", "bola", "access-control", "api-security"},
			},
			Metadata: map[string]any{
				"param_name":     param.Name(),
				"param_value":    param.Value(),
				"param_type":     param.Type().String(),
				"id_type":        classification.IDType.String(),
				"predictability": classification.Predictability.String(),
				"name_signal":    classification.NameSignal.String(),
				"total_score":    classification.TotalScore,
				"resource_noun":  classification.ResourceNoun,
				"is_path_param":  isPath,
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

// detectExcessiveData scans a JSON response body for sensitive field names.
func (m *Module) detectExcessiveData(body, host, urlStr string, ctx *httpmsg.HttpRequestResponse) []*output.ResultEvent {
	lowerBody := strings.ToLower(body)
	var sensitiveFields []string

	for field := range authzutil.SensitiveResponseFields {
		// Check for JSON key pattern: "field_name" followed by : or whitespace+:
		// Simple substring match on the lowercased field name is sufficient for triage
		if strings.Contains(lowerBody, `"`+field+`"`) {
			sensitiveFields = append(sensitiveFields, field)
		}
	}

	if len(sensitiveFields) == 0 {
		return nil
	}

	return []*output.ResultEvent{
		{
			ModuleID:         ModuleID,
			Host:             host,
			URL:              urlStr,
			Matched:          urlStr,
			Request:          string(ctx.Request().Raw()),
			ExtractedResults: sensitiveFields,
			Info: output.Info{
				Name:        "Excessive Data Exposure",
				Description: fmt.Sprintf("API response contains %d sensitive field(s): %s", len(sensitiveFields), strings.Join(sensitiveFields, ", ")),
				Severity:    severity.Low,
				Confidence:  severity.Tentative,
				Tags:        []string{"bopla", "excessive-data", "api-security"},
			},
			Metadata: map[string]any{
				"sensitive_fields": sensitiveFields,
				"field_count":      len(sensitiveFields),
			},
		},
	}
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
