package grpc_web_detect

import (
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra/grpcweb"
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
	// grpcDetected gates publishing the tech tag and the RPC-path indicator: it
	// is set only when we have a positive gRPC-Web signal (content type, decoded
	// trailer status, or grpc-status header) so a bare RPC-shaped URL never alone
	// produces a finding.
	grpcDetected := false

	// Detection 1: Response Content-Type
	if ctx.Response() != nil {
		rawRespCT := ctx.Response().Header("Content-Type")
		respCT := strings.ToLower(rawRespCT)
		for _, grpcCT := range grpcWebContentTypes {
			if strings.Contains(respCT, grpcCT) {
				indicators = append(indicators, fmt.Sprintf("Response Content-Type: %s", respCT))
				grpcDetected = true
				break
			}
		}

		// Detection 2: decode the gRPC-Web frames and surface the call's
		// grpc-status / grpc-message from the trailer frame. Preferred over the
		// grpc-status response header (which many gateways omit). Best-effort:
		// ignore decode errors and fall back to the header below.
		decodedStatus := ""
		if body := ctx.Response().Body(); len(body) > 0 {
			if ok, _ := grpcweb.IsGRPCWebContentType(rawRespCT); ok {
				frames, _ := grpcweb.DecodeBody(rawRespCT, body)
				for _, f := range frames {
					if !f.Trailer {
						continue
					}
					status, message, _ := grpcweb.ParseTrailer(f)
					if status == "" {
						continue
					}
					decodedStatus = status
					grpcDetected = true
					indicators = append(indicators, fmt.Sprintf("grpc-status: %s", status))
					if message != "" {
						indicators = append(indicators, fmt.Sprintf("grpc-message: %s", message))
					}
					break
				}
			}
		}

		// Fallback: grpc-status response header (only when no trailer decoded).
		if decodedStatus == "" {
			if grpcStatus := ctx.Response().Header("grpc-status"); grpcStatus != "" {
				indicators = append(indicators, fmt.Sprintf("grpc-status: %s", grpcStatus))
				grpcDetected = true
			}
		}
	}

	// Detection 3: Request Content-Type containing grpc
	if ctx.Request() != nil {
		reqCT := strings.ToLower(ctx.Request().Header("Content-Type"))
		if strings.Contains(reqCT, "grpc") {
			indicators = append(indicators, fmt.Sprintf("Request Content-Type: %s", reqCT))
			grpcDetected = true
		}
	}

	// Detection 4: the request path has the gRPC method shape /package.Service/Method.
	// Only recorded alongside a positive gRPC-Web signal so a REST path that merely
	// resembles the shape does not stand up a finding on its own.
	if grpcDetected && grpcweb.IsRPCPath(urlx.Path) {
		indicators = append(indicators, fmt.Sprintf("RPC: %s", urlx.Path))
	}

	if len(indicators) == 0 {
		return nil, nil
	}

	// Publish the tech tag once per host (this is the first-seen positive path;
	// subsequent requests for the host are dedup-skipped above). Nil-guarded.
	if grpcDetected {
		scanCtx.MarkTech(urlx.Host, "grpc-web")
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
