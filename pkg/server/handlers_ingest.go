package server

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/gofiber/fiber/v3"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/input/formats/curl"
	"github.com/vigolium/vigolium/pkg/input/formats/openapi"
	"github.com/vigolium/vigolium/pkg/input/formats/postman"
	"go.uber.org/zap"
)

// buildScopeMatchInput extracts scope-relevant fields from an HttpRequestResponse.
func buildScopeMatchInput(rr *httpmsg.HttpRequestResponse) config.ScopeMatchInput {
	input := config.ScopeMatchInput{
		Host:               rr.Service().Host(),
		Path:               rr.Request().Path(),
		RequestContentType: rr.Request().Header("Content-Type"),
		RequestRaw:         string(rr.Request().Raw()),
	}
	if rr.HasResponse() {
		resp := rr.Response()
		input.StatusCode = resp.StatusCode()
		input.ResponseContentType = resp.Header("Content-Type")
		input.ResponseBody = resp.BodyToString()
	}
	return input
}

// isIngestInScope checks whether a request/response pair should be saved.
// Static file filtering is always enforced (regardless of applied_on_ingest).
// Full scope rules are only enforced when applied_on_ingest is true.
func (h *Handlers) isIngestInScope(rr *httpmsg.HttpRequestResponse) bool {
	if h.settings == nil {
		return true
	}
	matcher := h.getScopeMatcher()
	if matcher == nil {
		return true
	}
	// Always filter static files regardless of applied_on_ingest
	if matcher.IsStaticFile(rr.Request().Path()) {
		return false
	}
	if !h.settings.Scope.AppliedOnIngest {
		return true
	}
	return matcher.InScope(buildScopeMatchInput(rr))
}

// fetchResponseIfNeeded fetches the HTTP response for a request if one isn't
// already attached and fetching is not disabled. On failure it returns the
// original request-only record so ingestion can proceed.
func (h *Handlers) fetchResponseIfNeeded(rr *httpmsg.HttpRequestResponse) *httpmsg.HttpRequestResponse {
	if rr.HasResponse() {
		return rr
	}
	if h.config.DisableFetchResponse || h.httpRequester == nil {
		return rr
	}

	respChain, _, err := h.httpRequester.Execute(rr, http.Options{})
	if err != nil {
		zap.L().Debug("Failed to fetch response during ingestion",
			zap.String("url", rr.Target()), zap.Error(err))
		return rr
	}

	fullResp := respChain.FullResponse().Bytes()
	raw := make([]byte, len(fullResp))
	copy(raw, fullResp)
	respChain.Close()

	return rr.WithResponse(httpmsg.NewHttpResponse(raw))
}

// saveRecord persists an HTTP record, routing through the RecordWriter when
// available (batched writes) or falling back to a direct repository insert.
func (h *Handlers) saveRecord(ctx context.Context, rr *httpmsg.HttpRequestResponse, source string, projectUUID string) (string, error) {
	if h.recordWriter != nil {
		return h.recordWriter.Write(ctx, rr, source, projectUUID)
	}
	return h.repo.SaveRecord(ctx, rr, source, projectUUID)
}

// HandleIngestHTTP handles POST /api/ingest-http
func (h *Handlers) HandleIngestHTTP(c fiber.Ctx) error {
	if h.repo == nil {
		return c.Status(fiber.StatusServiceUnavailable).JSON(ErrorResponse{
			Error: ErrDatabaseRequired.Error(),
			Code:  fiber.StatusServiceUnavailable,
		})
	}

	var req IngestHTTPRequest
	if err := c.Bind().JSON(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "invalid JSON: " + err.Error(),
			Code:  fiber.StatusBadRequest,
		})
	}

	if req.InputMode == "" {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: ErrMissingMode.Error(),
			Code:  fiber.StatusBadRequest,
		})
	}

	ctx := context.Background()

	switch req.InputMode {
	case "burp_base64":
		return h.ingestBurpBase64(c, ctx, &req)
	case "curl":
		return h.ingestCurl(c, ctx, &req)
	case "openapi", "swagger":
		return h.ingestOpenAPI(c, ctx, &req)
	case "postman_collection":
		return h.ingestPostman(c, ctx, &req)
	case "url":
		return h.ingestURL(c, ctx, &req)
	case "url_file":
		return h.ingestURLFile(c, ctx, &req)
	default:
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: ErrInvalidMode.Error(),
			Code:  fiber.StatusBadRequest,
		})
	}
}

// resolveContent returns content from the request, decoding base64 if needed.
func resolveContent(req *IngestHTTPRequest) (string, error) {
	if req.Content != "" {
		return req.Content, nil
	}
	if req.ContentBase64 != "" {
		data, err := base64.StdEncoding.DecodeString(req.ContentBase64)
		if err != nil {
			return "", fmt.Errorf("invalid base64 in content_base64: %w", err)
		}
		return string(data), nil
	}
	return "", ErrMissingContent
}

func (h *Handlers) ingestBurpBase64(c fiber.Ctx, ctx context.Context, req *IngestHTTPRequest) error {
	if req.HTTPRequestBase64 == "" {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "'http_request_base64' is required for burp_base64 mode",
			Code:  fiber.StatusBadRequest,
		})
	}

	rawReq, err := base64.StdEncoding.DecodeString(req.HTTPRequestBase64)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "invalid base64 in http_request_base64: " + err.Error(),
			Code:  fiber.StatusBadRequest,
		})
	}

	var rr *httpmsg.HttpRequestResponse
	if req.URL != "" {
		rr, err = httpmsg.ParseRawRequestWithURL(string(rawReq), req.URL)
	} else {
		rr, err = httpmsg.ParseRawRequest(string(rawReq))
	}
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "failed to parse raw request: " + err.Error(),
			Code:  fiber.StatusBadRequest,
		})
	}

	// Attach response if provided
	if req.HTTPResponseBase64 != "" {
		rawResp, err := base64.StdEncoding.DecodeString(req.HTTPResponseBase64)
		if err == nil {
			resp := httpmsg.NewHttpResponse(rawResp)
			if resp != nil {
				rr = rr.WithResponse(resp)
			}
		}
	}

	rr = h.fetchResponseIfNeeded(rr)

	if !h.isIngestInScope(rr) {
		return c.JSON(IngestHTTPResponse{
			ProjectUUID: getProjectUUID(c),
			Imported:    0,
			Skipped:     1,
			Message:     "filtered by scope",
		})
	}

	if _, err := h.saveRecord(ctx, rr, "ingest-server", getProjectUUID(c)); err != nil {
		zap.L().Error("Failed to save ingested record", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error: "failed to save record: " + err.Error(),
			Code:  fiber.StatusInternalServerError,
		})
	}

	return c.JSON(IngestHTTPResponse{
		ProjectUUID: getProjectUUID(c),
		Imported:    1,
		Message:     "imported 1 request",
	})
}

func (h *Handlers) ingestCurl(c fiber.Ctx, ctx context.Context, req *IngestHTTPRequest) error {
	content, err := resolveContent(req)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: err.Error(),
			Code:  fiber.StatusBadRequest,
		})
	}

	rr, err := curl.ParseSingleCommand(content)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "failed to parse curl command: " + err.Error(),
			Code:  fiber.StatusBadRequest,
		})
	}

	if req.URL != "" {
		if svc, svcErr := httpmsg.ParseService(req.URL); svcErr == nil {
			rr = rr.WithService(svc)
		}
	}

	rr = h.fetchResponseIfNeeded(rr)

	if !h.isIngestInScope(rr) {
		return c.JSON(IngestHTTPResponse{
			ProjectUUID: getProjectUUID(c),
			Imported:    0,
			Skipped:     1,
			Message:     "filtered by scope",
		})
	}

	if _, err := h.saveRecord(ctx, rr, "ingest-server", getProjectUUID(c)); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error: "failed to save record: " + err.Error(),
			Code:  fiber.StatusInternalServerError,
		})
	}

	return c.JSON(IngestHTTPResponse{
		ProjectUUID: getProjectUUID(c),
		Imported:    1,
		Message:     "imported 1 request from curl",
	})
}

func (h *Handlers) ingestOpenAPI(c fiber.Ctx, ctx context.Context, req *IngestHTTPRequest) error {
	content, err := resolveContent(req)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: err.Error(),
			Code:  fiber.StatusBadRequest,
		})
	}

	data := []byte(content)
	ext := openapi.DetectFormatFromContent(data)

	var imported, skipped int
	var errors []string

	var urlOverrideSvc *httpmsg.Service
	if req.URL != "" {
		if svc, svcErr := httpmsg.ParseService(req.URL); svcErr == nil {
			urlOverrideSvc = svc
		}
	}

	opts := openapi.Options{}
	if req.URL == "" {
		opts.UseSpecServers = true
	}
	parseErr := openapi.ParseSwagger(data, ext, opts, func(rr *httpmsg.HttpRequestResponse) bool {
		if urlOverrideSvc != nil {
			rr = rr.WithService(urlOverrideSvc)
		}
		rr = h.fetchResponseIfNeeded(rr)
		if !h.isIngestInScope(rr) {
			skipped++
			return true
		}
		if _, err := h.saveRecord(ctx, rr, "ingest-server", getProjectUUID(c)); err != nil {
			errors = append(errors, err.Error())
			return true // continue despite error
		}
		imported++
		return true
	})

	if parseErr != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "failed to parse OpenAPI spec: " + parseErr.Error(),
			Code:  fiber.StatusBadRequest,
		})
	}

	msg := fmt.Sprintf("imported %d requests from OpenAPI spec", imported)
	if skipped > 0 {
		msg += fmt.Sprintf(" (%d filtered by scope)", skipped)
	}

	return c.JSON(IngestHTTPResponse{
		ProjectUUID: getProjectUUID(c),
		Imported:    imported,
		Skipped:     skipped,
		Errors:      errors,
		Message:     msg,
	})
}

func (h *Handlers) ingestPostman(c fiber.Ctx, ctx context.Context, req *IngestHTTPRequest) error {
	content, err := resolveContent(req)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: err.Error(),
			Code:  fiber.StatusBadRequest,
		})
	}

	parser := postman.New()
	var imported, skipped int
	var errors []string

	var urlOverrideSvc *httpmsg.Service
	if req.URL != "" {
		if svc, svcErr := httpmsg.ParseService(req.URL); svcErr == nil {
			urlOverrideSvc = svc
		}
	}

	parseErr := parser.ParseFromData([]byte(content), func(rr *httpmsg.HttpRequestResponse) bool {
		if urlOverrideSvc != nil {
			rr = rr.WithService(urlOverrideSvc)
		}
		rr = h.fetchResponseIfNeeded(rr)
		if !h.isIngestInScope(rr) {
			skipped++
			return true
		}
		if _, err := h.saveRecord(ctx, rr, "ingest-server", getProjectUUID(c)); err != nil {
			errors = append(errors, err.Error())
			return true
		}
		imported++
		return true
	})

	if parseErr != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "failed to parse Postman collection: " + parseErr.Error(),
			Code:  fiber.StatusBadRequest,
		})
	}

	msg := fmt.Sprintf("imported %d requests from Postman collection", imported)
	if skipped > 0 {
		msg += fmt.Sprintf(" (%d filtered by scope)", skipped)
	}

	return c.JSON(IngestHTTPResponse{
		ProjectUUID: getProjectUUID(c),
		Imported:    imported,
		Skipped:     skipped,
		Errors:      errors,
		Message:     msg,
	})
}

func (h *Handlers) ingestURL(c fiber.Ctx, ctx context.Context, req *IngestHTTPRequest) error {
	content, err := resolveContent(req)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: err.Error(),
			Code:  fiber.StatusBadRequest,
		})
	}

	rr, err := httpmsg.GetRawRequestFromURL(strings.TrimSpace(content))
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "failed to create request from URL: " + err.Error(),
			Code:  fiber.StatusBadRequest,
		})
	}

	if req.URL != "" {
		if svc, svcErr := httpmsg.ParseService(req.URL); svcErr == nil {
			rr = rr.WithService(svc)
		}
	}

	rr = h.fetchResponseIfNeeded(rr)

	if !h.isIngestInScope(rr) {
		return c.JSON(IngestHTTPResponse{
			ProjectUUID: getProjectUUID(c),
			Imported:    0,
			Skipped:     1,
			Message:     "filtered by scope",
		})
	}

	if _, err := h.saveRecord(ctx, rr, "ingest-server", getProjectUUID(c)); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error: "failed to save record: " + err.Error(),
			Code:  fiber.StatusInternalServerError,
		})
	}

	return c.JSON(IngestHTTPResponse{
		ProjectUUID: getProjectUUID(c),
		Imported:    1,
		Message:     "imported 1 request from URL",
	})
}

func (h *Handlers) ingestURLFile(c fiber.Ctx, ctx context.Context, req *IngestHTTPRequest) error {
	content, err := resolveContent(req)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: err.Error(),
			Code:  fiber.StatusBadRequest,
		})
	}

	var imported, skipped int
	var errors []string

	var urlOverrideSvc *httpmsg.Service
	if req.URL != "" {
		if svc, svcErr := httpmsg.ParseService(req.URL); svcErr == nil {
			urlOverrideSvc = svc
		}
	}

	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		rr, err := httpmsg.GetRawRequestFromURL(line)
		if err != nil {
			errors = append(errors, fmt.Sprintf("%s: %s", line, err.Error()))
			continue
		}

		if urlOverrideSvc != nil {
			rr = rr.WithService(urlOverrideSvc)
		}

		rr = h.fetchResponseIfNeeded(rr)

		if !h.isIngestInScope(rr) {
			skipped++
			continue
		}

		if _, err := h.saveRecord(ctx, rr, "ingest-server", getProjectUUID(c)); err != nil {
			errors = append(errors, fmt.Sprintf("%s: %s", line, err.Error()))
			continue
		}
		imported++
	}

	msg := fmt.Sprintf("imported %d requests from URL list", imported)
	if skipped > 0 {
		msg += fmt.Sprintf(" (%d filtered by scope)", skipped)
	}

	return c.JSON(IngestHTTPResponse{
		ProjectUUID: getProjectUUID(c),
		Imported:    imported,
		Skipped:     skipped,
		Errors:      errors,
		Message:     msg,
	})
}
