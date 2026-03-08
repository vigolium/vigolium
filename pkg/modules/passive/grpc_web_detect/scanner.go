package grpc_web_detect

import (
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/utils"
)

// grpcWebContentTypes lists gRPC-Web response content types.
var grpcWebContentTypes = []string{
	"application/grpc-web",
	"application/grpc-web+proto",
	"application/grpc-web-text",
}

// Module implements the gRPC-Web Detect passive scanner.
type Module struct {
	modkit.BasePassiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new gRPC-Web Detect module.
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
		ds: dedup.LazyDiskSet("passive_grpc_web_detect"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerRequest analyzes request and response for gRPC-Web indicators.
func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	urlx, err := ctx.URL()
	if err != nil {
		return nil, nil
	}

	diskSet := m.ds.Get(scanCtx.DedupMgr())
	dedupKey := utils.Sha1(urlx.Host)
	if diskSet != nil && diskSet.IsSeen(dedupKey) {
		return nil, nil
	}

	var indicators []string

	// Detection 1: Response Content-Type
	if ctx.Response() != nil {
		respCT := strings.ToLower(ctx.Response().Header("Content-Type"))
		for _, grpcCT := range grpcWebContentTypes {
			if strings.Contains(respCT, grpcCT) {
				indicators = append(indicators, fmt.Sprintf("Response Content-Type: %s", respCT))
				break
			}
		}

		// Detection 2: grpc-status response header
		if grpcStatus := ctx.Response().Header("grpc-status"); grpcStatus != "" {
			indicators = append(indicators, fmt.Sprintf("grpc-status: %s", grpcStatus))
		}
	}

	// Detection 3: Request Content-Type containing grpc
	if ctx.Request() != nil {
		reqCT := strings.ToLower(ctx.Request().Header("Content-Type"))
		if strings.Contains(reqCT, "grpc") {
			indicators = append(indicators, fmt.Sprintf("Request Content-Type: %s", reqCT))
		}
	}

	if len(indicators) == 0 {
		return nil, nil
	}

	return []*output.ResultEvent{
		{
			ModuleID:         ModuleID,
			Host:             urlx.Host,
			URL:              urlx.String(),
			Matched:          urlx.String(),
			ExtractedResults: indicators,
			Info: output.Info{
				Name:        "gRPC-Web Endpoint Detected",
				Description: fmt.Sprintf("gRPC-Web protocol detected with %d indicator(s)", len(indicators)),
				Tags:        []string{"grpc-web", "api-protocol"},
			},
		},
	}, nil
}
