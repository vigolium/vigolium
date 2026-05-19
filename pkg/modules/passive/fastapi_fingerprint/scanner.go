package fastapi_fingerprint

import (
	"strings"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// Module implements the FastAPI Fingerprint passive scanner.
type Module struct {
	modkit.BasePassiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new FastAPI Fingerprint module.
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
		ds: dedup.LazyDiskSet("fastapi_fingerprint"),
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

	hdr := func(name string) string { return ctx.Response().Header(name) }
	body := ctx.Response().BodyToString()
	statusCode := ctx.Response().StatusCode()

	var extracted []string
	meta := map[string]any{
		"platform": "fastapi",
	}

	signalCount := 0

	// Signal 1: Server header contains "uvicorn" (case-insensitive)
	serverHdr := strings.ToLower(hdr("Server"))
	if strings.Contains(serverHdr, "uvicorn") {
		signalCount++
		extracted = append(extracted, "Server: uvicorn")
		meta["server"] = "uvicorn"
	}

	// Signal 2: Response body contains {"detail": error shape on 4xx/5xx
	if statusCode >= 400 && statusCode < 600 {
		if strings.Contains(body, `{"detail":`) || strings.Contains(body, `{ "detail":`) {
			signalCount++
			extracted = append(extracted, "Body: FastAPI error shape ({\"detail\":...})")
		}
	}

	// Signal 3: Response body contains OpenAPI spec indicators
	if strings.Contains(body, `"openapi"`) && strings.Contains(body, `"paths"`) {
		signalCount++
		extracted = append(extracted, "Body: OpenAPI spec indicators (openapi + paths)")
		meta["hasOpenAPISpec"] = true
	}

	// Signal 4: URL path is /docs or /redoc with expected body content
	pathLower := strings.ToLower(urlx.Path)
	if (pathLower == "/docs" || pathLower == "/redoc") &&
		(strings.Contains(body, "swagger-ui") || strings.Contains(body, "redoc")) {
		signalCount++
		extracted = append(extracted, "Path: "+urlx.Path+" (API documentation endpoint)")
		meta["hasAPIDocs"] = true
	}

	// Signal 5: x-process-time header present (common FastAPI middleware)
	if hdr("x-process-time") != "" {
		signalCount++
		extracted = append(extracted, "Header: x-process-time: "+hdr("x-process-time"))
	}

	// Require 2+ signals to report
	if signalCount < 2 {
		return nil, nil
	}

	desc := "FastAPI/Starlette application detected"
	if server, ok := meta["server"]; ok {
		desc += " running on " + server.(string)
	}

	scanCtx.MarkTech(host, "fastapi")
	scanCtx.MarkTech(host, "python")

	return []*output.ResultEvent{
		{
			ModuleID:         ModuleID,
			Host:             host,
			URL:              urlx.String(),
			Matched:          urlx.String(),
			ExtractedResults: extracted,
			Info: output.Info{
				Name:        "FastAPI/Starlette Application Detected",
				Description: desc,
				Severity:    severity.Info,
				Confidence:  severity.Certain,
				Tags:        []string{"python", "fastapi", "starlette", "fingerprint"},
				Reference:   []string{"https://fastapi.tiangolo.com/"},
			},
			Metadata: meta,
		},
	}, nil
}
