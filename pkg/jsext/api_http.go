package jsext

import (
	"fmt"
	"strings"

	"github.com/grafana/sobek"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"go.uber.org/zap"
)

// setupHTTPAPI registers vigolium.http.* functions on the VM.
// These bridge JS HTTP calls to the Go Requester.
func setupHTTPAPI(vm *sobek.Runtime, httpClient *http.Requester) {
	httpObj := vm.NewObject()

	// vigolium.http.get(url, opts?) -> {status, headers, body}
	_ = httpObj.Set("get", func(call sobek.FunctionCall) sobek.Value {
		urlStr := call.Argument(0).String()
		return doSimpleRequest(vm, httpClient, "GET", urlStr, "", call.Argument(1))
	})

	// vigolium.http.post(url, body, opts?) -> {status, headers, body}
	_ = httpObj.Set("post", func(call sobek.FunctionCall) sobek.Value {
		urlStr := call.Argument(0).String()
		body := call.Argument(1).String()
		return doSimpleRequest(vm, httpClient, "POST", urlStr, body, call.Argument(2))
	})

	// vigolium.http.request({method, url, headers, body}) -> {status, headers, body}
	_ = httpObj.Set("request", func(call sobek.FunctionCall) sobek.Value {
		optsVal := call.Argument(0)
		if sobek.IsUndefined(optsVal) || sobek.IsNull(optsVal) {
			return sobek.Undefined()
		}
		opts := optsVal.ToObject(vm)

		method := "GET"
		if v := opts.Get("method"); v != nil && !sobek.IsUndefined(v) {
			method = strings.ToUpper(v.String())
		}
		urlStr := ""
		if v := opts.Get("url"); v != nil && !sobek.IsUndefined(v) {
			urlStr = v.String()
		}
		body := ""
		if v := opts.Get("body"); v != nil && !sobek.IsUndefined(v) {
			body = v.String()
		}

		headers := make(map[string]string)
		if v := opts.Get("headers"); v != nil && !sobek.IsUndefined(v) {
			headersObj := v.ToObject(vm)
			for _, key := range headersObj.Keys() {
				headers[key] = headersObj.Get(key).String()
			}
		}

		return doRequest(vm, httpClient, method, urlStr, body, headers)
	})

	// vigolium.http.send(rawRequest) -> {status, headers, body}
	_ = httpObj.Set("send", func(call sobek.FunctionCall) sobek.Value {
		rawReq := call.Argument(0).String()
		return doRawRequest(vm, httpClient, rawReq)
	})

	vigolium := vm.Get("vigolium").ToObject(vm)
	_ = vigolium.Set("http", httpObj)
}

func doSimpleRequest(vm *sobek.Runtime, httpClient *http.Requester, method, urlStr, body string, optsVal sobek.Value) sobek.Value {
	headers := make(map[string]string)

	if optsVal != nil && !sobek.IsUndefined(optsVal) && !sobek.IsNull(optsVal) {
		opts := optsVal.ToObject(vm)
		if v := opts.Get("headers"); v != nil && !sobek.IsUndefined(v) {
			headersObj := v.ToObject(vm)
			for _, key := range headersObj.Keys() {
				headers[key] = headersObj.Get(key).String()
			}
		}
	}

	return doRequest(vm, httpClient, method, urlStr, body, headers)
}

func doRequest(vm *sobek.Runtime, httpClient *http.Requester, method, urlStr, body string, headers map[string]string) sobek.Value {
	// Build raw HTTP request
	var sb strings.Builder
	fmt.Fprintf(&sb, "%s %s HTTP/1.1\r\n", method, urlStr)

	// Extract host from URL
	host := extractHost(urlStr)
	fmt.Fprintf(&sb, "Host: %s\r\n", host)

	for k, v := range headers {
		if strings.EqualFold(k, "host") {
			continue
		}
		fmt.Fprintf(&sb, "%s: %s\r\n", k, v)
	}

	if body != "" && headers["Content-Length"] == "" {
		fmt.Fprintf(&sb, "Content-Length: %d\r\n", len(body))
	}
	sb.WriteString("\r\n")
	if body != "" {
		sb.WriteString(body)
	}

	return doRawRequest(vm, httpClient, sb.String())
}

func doRawRequest(vm *sobek.Runtime, httpClient *http.Requester, rawReq string) sobek.Value {
	req := httpmsg.NewHttpRequest([]byte(rawReq))

	// Infer service from Host header so the requester knows where to connect
	if host := req.Header("Host"); host != "" {
		svc, err := httpmsg.ParseService("http://" + host)
		if err == nil {
			req = httpmsg.NewHttpRequestWithService(svc, []byte(rawReq))
		}
	}

	hrr := httpmsg.NewHttpRequestResponse(req, nil)

	respChain, _, err := httpClient.Execute(hrr, http.Options{})
	if err != nil {
		zap.L().Debug("JS HTTP request failed", zap.Error(err))
		return sobek.Undefined()
	}

	fullResp := respChain.FullResponse().Bytes()
	rawResponseCopy := make([]byte, len(fullResp))
	copy(rawResponseCopy, fullResp)
	respChain.Close()

	httpResp := httpmsg.NewHttpResponse(rawResponseCopy)

	result := vm.NewObject()
	_ = result.Set("status", httpResp.StatusCode())
	_ = result.Set("body", string(httpResp.Body()))
	_ = result.Set("raw", string(rawResponseCopy))

	// Parse response headers into JS object
	headersObj := vm.NewObject()
	for _, h := range httpResp.Headers() {
		_ = headersObj.Set(strings.ToLower(h.Name), h.Value)
	}
	_ = result.Set("headers", headersObj)

	return result
}

func extractHost(rawURL string) string {
	if idx := strings.Index(rawURL, "://"); idx != -1 {
		rest := rawURL[idx+3:]
		if slashIdx := strings.Index(rest, "/"); slashIdx != -1 {
			return rest[:slashIdx]
		}
		return rest
	}
	if slashIdx := strings.Index(rawURL, "/"); slashIdx != -1 {
		return rawURL[:slashIdx]
	}
	return rawURL
}
