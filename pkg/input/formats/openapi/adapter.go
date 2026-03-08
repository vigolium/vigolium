package openapi

import (
	"net/http/httputil"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"go.uber.org/zap"
)

// ServerScanRequest is a lightweight scan request type used by the adapter
// to avoid importing pkg/server/api (which would create a cycle).
type ServerScanRequest struct {
	URL           string
	RawRequest    string
	EnableModules []string
	WebhookURL    string
}

// ParseForServer parses an OpenAPI spec and calls callback with ServerScanRequest.
func ParseForServer(data []byte, opts ServerOptions, callback func(*ServerScanRequest)) error {
	wrappedCallback := func(rr *httpmsg.HttpRequestResponse) bool {
		scanReq := convertToServerScanRequest(rr, opts)
		if scanReq != nil {
			callback(scanReq)
		}
		return true
	}

	return ParseOpenAPI(data, opts.Options, wrappedCallback)
}

// ParseSwaggerForServer parses a Swagger spec and calls callback with ServerScanRequest.
func ParseSwaggerForServer(data []byte, ext string, opts ServerOptions, callback func(*ServerScanRequest)) error {
	wrappedCallback := func(rr *httpmsg.HttpRequestResponse) bool {
		scanReq := convertToServerScanRequest(rr, opts)
		if scanReq != nil {
			callback(scanReq)
		}
		return true
	}

	return ParseSwagger(data, ext, opts.Options, wrappedCallback)
}

func convertToServerScanRequest(rr *httpmsg.HttpRequestResponse, opts ServerOptions) *ServerScanRequest {
	if rr == nil || rr.Request() == nil {
		return nil
	}

	req, err := rr.BuildRetryableRequest()
	if err != nil {
		zap.L().Debug("Failed to build request", zap.Error(err))
		return nil
	}

	dumped, err := httputil.DumpRequestOut(req.Request, true)
	if err != nil {
		zap.L().Debug("Failed to dump request", zap.Error(err))
		return nil
	}

	return &ServerScanRequest{
		URL:           req.String(),
		RawRequest:    string(dumped),
		EnableModules: opts.EnableModules,
		WebhookURL:    opts.WebhookURL,
	}
}
