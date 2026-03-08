package jsext

import (
	"context"
	"fmt"
	"strings"

	"github.com/grafana/sobek"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/input/formats/curl"
	"github.com/vigolium/vigolium/pkg/input/formats/openapi"
	"github.com/vigolium/vigolium/pkg/input/formats/postman"
	"go.uber.org/zap"
)

const ingestSource = "ingest-extension"

// setupIngestAPI registers vigolium.ingest.* functions on the VM.
func setupIngestAPI(vm *sobek.Runtime, opts APIOptions) {
	ingestObj := vm.NewObject()

	repo := opts.Repository

	// vigolium.ingest.url(url) -> IngestResult
	_ = ingestObj.Set("url", func(call sobek.FunctionCall) sobek.Value {
		if repo == nil {
			return ingestResultToJS(vm, 0, 0, "", "database not available")
		}

		urlStr := strings.TrimSpace(call.Argument(0).String())
		if urlStr == "" {
			return ingestResultToJS(vm, 0, 0, "", "url is required")
		}

		rr, err := httpmsg.GetRawRequestFromURL(urlStr)
		if err != nil {
			return ingestResultToJS(vm, 0, 0, "", fmt.Sprintf("failed to parse URL: %s", err))
		}

		rr = fetchResponseForIngest(rr, opts.HTTPClient)

		if !isExtIngestInScope(opts.ScopeMatcher, rr) {
			return ingestResultToJS(vm, 0, 1, "", "")
		}

		uuid, err := repo.SaveRecord(context.Background(), rr, ingestSource, opts.ProjectUUID)
		if err != nil {
			return ingestResultToJS(vm, 0, 0, "", fmt.Sprintf("failed to save: %s", err))
		}

		return ingestResultToJS(vm, 1, 0, uuid, "")
	})

	// vigolium.ingest.urls(content) -> IngestBatchResult
	_ = ingestObj.Set("urls", func(call sobek.FunctionCall) sobek.Value {
		if repo == nil {
			return ingestBatchResultToJS(vm, 0, 0, []string{"database not available"})
		}

		content := call.Argument(0).String()
		var imported, skipped int
		var errors []string

		lines := strings.Split(content, "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}

			rr, err := httpmsg.GetRawRequestFromURL(line)
			if err != nil {
				errors = append(errors, fmt.Sprintf("%s: %s", line, err))
				continue
			}

			rr = fetchResponseForIngest(rr, opts.HTTPClient)

			if !isExtIngestInScope(opts.ScopeMatcher, rr) {
				skipped++
				continue
			}

			if _, err := repo.SaveRecord(context.Background(), rr, ingestSource, opts.ProjectUUID); err != nil {
				errors = append(errors, fmt.Sprintf("%s: %s", line, err))
				continue
			}
			imported++
		}

		return ingestBatchResultToJS(vm, imported, skipped, errors)
	})

	// vigolium.ingest.curl(command) -> IngestResult
	_ = ingestObj.Set("curl", func(call sobek.FunctionCall) sobek.Value {
		if repo == nil {
			return ingestResultToJS(vm, 0, 0, "", "database not available")
		}

		command := call.Argument(0).String()
		if command == "" {
			return ingestResultToJS(vm, 0, 0, "", "curl command is required")
		}

		rr, err := curl.ParseSingleCommand(command)
		if err != nil {
			return ingestResultToJS(vm, 0, 0, "", fmt.Sprintf("failed to parse curl: %s", err))
		}

		rr = fetchResponseForIngest(rr, opts.HTTPClient)

		if !isExtIngestInScope(opts.ScopeMatcher, rr) {
			return ingestResultToJS(vm, 0, 1, "", "")
		}

		uuid, err := repo.SaveRecord(context.Background(), rr, ingestSource, opts.ProjectUUID)
		if err != nil {
			return ingestResultToJS(vm, 0, 0, "", fmt.Sprintf("failed to save: %s", err))
		}

		return ingestResultToJS(vm, 1, 0, uuid, "")
	})

	// vigolium.ingest.raw(rawRequest, rawResponse?) -> IngestResult
	_ = ingestObj.Set("raw", func(call sobek.FunctionCall) sobek.Value {
		if repo == nil {
			return ingestResultToJS(vm, 0, 0, "", "database not available")
		}

		rawReq := call.Argument(0).String()
		if rawReq == "" {
			return ingestResultToJS(vm, 0, 0, "", "raw request is required")
		}

		rr, err := httpmsg.ParseRawRequest(rawReq)
		if err != nil {
			return ingestResultToJS(vm, 0, 0, "", fmt.Sprintf("failed to parse raw request: %s", err))
		}

		// Attach response if provided
		rawResp := call.Argument(1)
		if !sobek.IsUndefined(rawResp) && !sobek.IsNull(rawResp) {
			respStr := rawResp.String()
			if respStr != "" {
				resp := httpmsg.NewHttpResponse([]byte(respStr))
				if resp != nil {
					rr = rr.WithResponse(resp)
				}
			}
		}

		rr = fetchResponseForIngest(rr, opts.HTTPClient)

		if !isExtIngestInScope(opts.ScopeMatcher, rr) {
			return ingestResultToJS(vm, 0, 1, "", "")
		}

		uuid, err := repo.SaveRecord(context.Background(), rr, ingestSource, opts.ProjectUUID)
		if err != nil {
			return ingestResultToJS(vm, 0, 0, "", fmt.Sprintf("failed to save: %s", err))
		}

		return ingestResultToJS(vm, 1, 0, uuid, "")
	})

	// vigolium.ingest.openapi(spec, opts?) -> IngestBatchResult
	_ = ingestObj.Set("openapi", func(call sobek.FunctionCall) sobek.Value {
		if repo == nil {
			return ingestBatchResultToJS(vm, 0, 0, []string{"database not available"})
		}

		specContent := call.Argument(0).String()
		if specContent == "" {
			return ingestBatchResultToJS(vm, 0, 0, []string{"spec content is required"})
		}

		// Parse optional opts.base_url
		var oaOpts openapi.Options
		optsArg := call.Argument(1)
		if !sobek.IsUndefined(optsArg) && !sobek.IsNull(optsArg) {
			obj := optsArg.ToObject(vm)
			if v := obj.Get("base_url"); v != nil && !sobek.IsUndefined(v) {
				oaOpts.BaseURL = v.String()
			}
		}

		data := []byte(specContent)
		ext := openapi.DetectFormatFromContent(data)

		var imported, skipped int
		var errors []string

		parseErr := openapi.ParseSwagger(data, ext, oaOpts, func(rr *httpmsg.HttpRequestResponse) bool {
			rr = fetchResponseForIngest(rr, opts.HTTPClient)
			if !isExtIngestInScope(opts.ScopeMatcher, rr) {
				skipped++
				return true
			}
			if _, err := repo.SaveRecord(context.Background(), rr, ingestSource, opts.ProjectUUID); err != nil {
				errors = append(errors, err.Error())
				return true
			}
			imported++
			return true
		})

		if parseErr != nil {
			errors = append(errors, fmt.Sprintf("failed to parse OpenAPI spec: %s", parseErr))
		}

		return ingestBatchResultToJS(vm, imported, skipped, errors)
	})

	// vigolium.ingest.postman(collection) -> IngestBatchResult
	_ = ingestObj.Set("postman", func(call sobek.FunctionCall) sobek.Value {
		if repo == nil {
			return ingestBatchResultToJS(vm, 0, 0, []string{"database not available"})
		}

		content := call.Argument(0).String()
		if content == "" {
			return ingestBatchResultToJS(vm, 0, 0, []string{"collection content is required"})
		}

		parser := postman.New()
		var imported, skipped int
		var errors []string

		parseErr := parser.ParseFromData([]byte(content), func(rr *httpmsg.HttpRequestResponse) bool {
			rr = fetchResponseForIngest(rr, opts.HTTPClient)
			if !isExtIngestInScope(opts.ScopeMatcher, rr) {
				skipped++
				return true
			}
			if _, err := repo.SaveRecord(context.Background(), rr, ingestSource, opts.ProjectUUID); err != nil {
				errors = append(errors, err.Error())
				return true
			}
			imported++
			return true
		})

		if parseErr != nil {
			errors = append(errors, fmt.Sprintf("failed to parse Postman collection: %s", parseErr))
		}

		return ingestBatchResultToJS(vm, imported, skipped, errors)
	})

	vigolium := vm.Get("vigolium").ToObject(vm)
	_ = vigolium.Set("ingest", ingestObj)
}

// fetchResponseForIngest fetches the HTTP response for a request if one isn't
// already attached. On failure it returns the original request-only record.
func fetchResponseForIngest(rr *httpmsg.HttpRequestResponse, httpClient *http.Requester) *httpmsg.HttpRequestResponse {
	if rr.HasResponse() || httpClient == nil {
		return rr
	}

	respChain, _, err := httpClient.Execute(rr, http.Options{})
	if err != nil {
		zap.L().Debug("Failed to fetch response during extension ingest",
			zap.String("url", rr.Target()), zap.Error(err))
		return rr
	}

	fullResp := respChain.FullResponse().Bytes()
	raw := make([]byte, len(fullResp))
	copy(raw, fullResp)
	respChain.Close()

	return rr.WithResponse(httpmsg.NewHttpResponse(raw))
}

// isExtIngestInScope checks whether a request/response pair should be saved.
// Static file filtering is always enforced when a scopeMatcher is available.
// Full scope rules are also checked when the matcher is present.
// Returns true when scopeMatcher is nil (no scope filtering).
func isExtIngestInScope(scopeMatcher *config.ScopeMatcher, rr *httpmsg.HttpRequestResponse) bool {
	if scopeMatcher == nil {
		return true
	}

	// Always filter static files
	if scopeMatcher.IsStaticFile(rr.Request().Path()) {
		return false
	}

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

	return scopeMatcher.InScope(input)
}

// ingestResultToJS creates a JS IngestResult object.
func ingestResultToJS(vm *sobek.Runtime, imported, skipped int, uuid, errMsg string) sobek.Value {
	obj := vm.NewObject()
	_ = obj.Set("imported", imported)
	_ = obj.Set("skipped", skipped)
	_ = obj.Set("uuid", uuid)
	_ = obj.Set("error", errMsg)
	return obj
}

// ingestBatchResultToJS creates a JS IngestBatchResult object.
func ingestBatchResultToJS(vm *sobek.Runtime, imported, skipped int, errors []string) sobek.Value {
	obj := vm.NewObject()
	_ = obj.Set("imported", imported)
	_ = obj.Set("skipped", skipped)
	if errors == nil {
		errors = []string{}
	}
	_ = obj.Set("errors", errors)
	return obj
}
