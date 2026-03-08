package endpoint_classifier

import (
	"context"
	"strings"

	"go.uber.org/zap"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
)

// Module implements a passive module that classifies HTTP endpoints
// and annotates database records with semantic tags.
type Module struct {
	modkit.BasePassiveModule
}

// New creates a new endpoint classifier passive module.
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
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerRequest classifies the endpoint and annotates the record with semantic tags.
func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	if scanCtx == nil || scanCtx.RemarksAnnotator == nil || scanCtx.RequestUUIDResolver == nil {
		return nil, nil
	}

	tags := m.classify(ctx)
	if len(tags) == 0 {
		return nil, nil
	}

	uuid := scanCtx.RequestUUIDResolver.ResolveRequestUUID(ctx.Request().ID())
	if uuid == "" {
		return nil, nil
	}

	if err := scanCtx.RemarksAnnotator.AppendRemarks(context.Background(), map[string][]string{uuid: tags}); err != nil {
		zap.L().Debug("endpoint_classifier: failed to annotate", zap.Error(err))
	}

	return nil, nil
}

// classify derives semantic tags from request/response characteristics.
func (m *Module) classify(ctx *httpmsg.HttpRequestResponse) []string {
	var tags []string

	req := ctx.Request()
	path := strings.ToLower(req.Path())

	// Path-based classification
	if strings.Contains(path, "/graphql") {
		tags = append(tags, "graphql")
	}
	if strings.HasPrefix(path, "/api/") || strings.Contains(path, "/api/") {
		tags = append(tags, "api-endpoint")
	}

	// Request characteristics
	reqCT := strings.ToLower(req.Header("Content-Type"))
	if strings.Contains(reqCT, "multipart/form-data") {
		tags = append(tags, "file-upload")
	}
	if strings.Contains(reqCT, "application/x-www-form-urlencoded") {
		tags = append(tags, "form-endpoint")
	}

	// Authentication
	if req.Header("Authorization") != "" {
		tags = append(tags, "authenticated")
	}

	// Response characteristics
	if ctx.Response() == nil {
		return tags
	}

	statusCode := ctx.Response().StatusCode()
	respCT := strings.ToLower(ctx.Response().Header("Content-Type"))

	// Content type classification
	if strings.Contains(respCT, "application/json") || strings.Contains(respCT, "+json") {
		tags = append(tags, "json-api")
	}
	if strings.Contains(respCT, "text/html") {
		tags = append(tags, "html-page")
	}
	if strings.Contains(respCT, "application/xml") || strings.Contains(respCT, "text/xml") {
		tags = append(tags, "xml-api")
	}

	// Status code classification
	switch {
	case statusCode == 301 || statusCode == 302 || statusCode == 307 || statusCode == 308:
		tags = append(tags, "redirect")
	case statusCode >= 400 && statusCode < 600:
		tags = append(tags, "error-page")
	}

	return tags
}
