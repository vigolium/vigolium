package drupal_api_detect

import (
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/pkg/errors"
)

type Module struct {
	modkit.BasePassiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

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
		ds: dedup.LazyDiskSet("drupal_api_detect"),
	}
	m.ModuleTags = ModuleTags
	return m
}

func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	if !ctx.HasResponse() {
		return nil, nil
	}

	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	host := urlx.Host

	diskSet := m.ds.Get(scanCtx.DedupMgr())
	if diskSet != nil && diskSet.IsSeen(host) {
		return nil, nil
	}

	ct := strings.ToLower(ctx.Response().Header("Content-Type"))
	body := ctx.Response().BodyToString()
	path := strings.ToLower(urlx.Path)

	var signals []string
	apiType := ""
	hasContentSignal := false

	// JSON:API detection via content type
	if strings.Contains(ct, "application/vnd.api+json") {
		apiType = "JSON:API"
		signals = append(signals, "application/vnd.api+json content type")
		hasContentSignal = true
	}

	// JSON:API link patterns in body
	if strings.Contains(body, `"jsonapi"`) && strings.Contains(body, `"links"`) {
		if apiType == "" {
			apiType = "JSON:API"
		}
		signals = append(signals, "JSON:API resource structure in response body")
		hasContentSignal = true
	}

	// Drupal REST responses (HAL+JSON with _links and type is Drupal-specific)
	if strings.Contains(ct, "application/hal+json") {
		if apiType == "" {
			apiType = "REST (HAL)"
		}
		signals = append(signals, "application/hal+json content type")
		hasContentSignal = true
	}
	if (strings.Contains(ct, "application/json") || strings.Contains(ct, "application/hal+json")) &&
		strings.Contains(body, `"_links"`) && strings.Contains(body, `"type"`) {
		if apiType == "" {
			apiType = "REST (HAL)"
		}
		signals = append(signals, "HAL+JSON entity structure")
		hasContentSignal = true
	}

	// Drupal-specific headers
	if strings.Contains(strings.ToLower(ctx.Response().Header("X-Generator")), "drupal") ||
		ctx.Response().Header("X-Drupal-Cache") != "" ||
		ctx.Response().Header("X-Drupal-Dynamic-Cache") != "" {
		hasContentSignal = true
		signals = append(signals, "Drupal-specific response header")
	}

	// Path-based signals (supplementary only — not sufficient on their own)
	if strings.HasPrefix(path, "/jsonapi") {
		if apiType == "" {
			apiType = "JSON:API"
		}
		signals = append(signals, fmt.Sprintf("JSON:API path: %s", urlx.Path))
	}
	query := strings.ToLower(urlx.RawQuery)
	if strings.Contains(query, "_format=json") || strings.Contains(query, "_format=hal_json") {
		if apiType == "" {
			apiType = "REST"
		}
		signals = append(signals, fmt.Sprintf("Drupal REST format parameter: %s", urlx.RawQuery))
	}

	// Require at least one content-based signal (content type, body structure, or Drupal header).
	// Path-only matches are too generic and cause false positives on non-Drupal apps.
	if !hasContentSignal || len(signals) == 0 {
		return nil, nil
	}

	return []*output.ResultEvent{
		{
			ModuleID:         ModuleID,
			Host:             host,
			URL:              urlx.String(),
			Matched:          urlx.String(),
			ExtractedResults: signals,
			Info: output.Info{
				Name:        fmt.Sprintf("Drupal %s Exposure", apiType),
				Description: fmt.Sprintf("Drupal %s detected via %s", apiType, strings.Join(signals, ", ")),
				Severity:    severity.Low,
				Confidence:  severity.Certain,
				Tags:        []string{"cms", "drupal", "api-exposure"},
			},
			Metadata: map[string]any{
				"cms":     "drupal",
				"apiType": apiType,
			},
		},
	}, nil
}
