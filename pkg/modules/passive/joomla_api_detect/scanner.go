package joomla_api_detect

import (
	"fmt"
	"strings"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
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
		ds: dedup.LazyDiskSet("joomla_api_detect"),
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
	isJoomlaAPI := false

	// Path-based: /api/index.php
	if strings.Contains(path, "/api/index.php") {
		isJoomlaAPI = true
		signals = append(signals, fmt.Sprintf("Joomla API path: %s", urlx.Path))
	}

	// Content-type: application/vnd.api+json (JSON:API used by Joomla 4+)
	if strings.Contains(ct, "application/vnd.api+json") && isJoomlaAPI {
		signals = append(signals, "application/vnd.api+json content type")
	}

	// JSON:API response body with Joomla resource patterns
	if isJoomlaAPI && strings.Contains(body, `"links"`) && strings.Contains(body, `"data"`) {
		signals = append(signals, "JSON:API resource structure in response")
	}

	// CORS header check on API endpoints
	if isJoomlaAPI {
		acao := ctx.Response().Header("Access-Control-Allow-Origin")
		if acao == "*" {
			signals = append(signals, "Overly permissive CORS: Access-Control-Allow-Origin: *")
		}
	}

	if !isJoomlaAPI || len(signals) == 0 {
		return nil, nil
	}

	sev := severity.Low
	// Escalate if CORS is wide open on API
	for _, s := range signals {
		if strings.Contains(s, "CORS") {
			sev = severity.Medium
			break
		}
	}

	return []*output.ResultEvent{
		{
			ModuleID:         ModuleID,
			Host:             host,
			URL:              urlx.String(),
			Matched:          urlx.String(),
			ExtractedResults: signals,
			Info: output.Info{
				Name:        "Joomla Web Services API Exposure",
				Description: fmt.Sprintf("Joomla Web Services API (J4+) detected via %s", strings.Join(signals, ", ")),
				Severity:    sev,
				Confidence:  severity.Certain,
				Tags:        []string{"cms", "joomla", "api-exposure"},
			},
			Metadata: map[string]any{
				"cms": "joomla",
			},
		},
	}, nil
}
