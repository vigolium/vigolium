package jsext

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/grafana/sobek"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/jsext/api/parse"
	"go.uber.org/zap"
)

// httpCoreFuncDefs returns JSFuncDefs for the core vigolium.http.* functions.
func httpCoreFuncDefs() []JSFuncDef {
	return []JSFuncDef{
		{
			Namespace:   NsHTTP,
			Name:        "get",
			Effect:      EffectNetwork,
			Category:    CatHTTP,
			Signature:   ".get(url: string, opts?: {headers})",
			Returns:     "{status, headers, body, raw}",
			Description: "Send an HTTP GET request.",
			Example:     exHTTPGet,
			MakeHandler: func(vm *sobek.Runtime, opts APIOptions) func(sobek.FunctionCall) sobek.Value {
				return func(call sobek.FunctionCall) sobek.Value {
					urlStr := call.Argument(0).String()
					return doSimpleRequest(vm, opts.HTTPClient, "GET", urlStr, "", call.Argument(1))
				}
			},
		},
		{
			Namespace:   NsHTTP,
			Name:        "post",
			Effect:      EffectNetwork,
			Category:    CatHTTP,
			Signature:   ".post(url: string, body: string, opts?: {headers})",
			Returns:     "{status, headers, body, raw}",
			Description: "Send an HTTP POST request.",
			Example:     exHTTPPost,
			MakeHandler: func(vm *sobek.Runtime, opts APIOptions) func(sobek.FunctionCall) sobek.Value {
				return func(call sobek.FunctionCall) sobek.Value {
					urlStr := call.Argument(0).String()
					body := call.Argument(1).String()
					return doSimpleRequest(vm, opts.HTTPClient, "POST", urlStr, body, call.Argument(2))
				}
			},
		},
		{
			Namespace:   NsHTTP,
			Name:        "request",
			Effect:      EffectNetwork,
			Category:    CatHTTP,
			Signature:   ".request({method, url, headers, body})",
			Returns:     "{status, headers, body, raw}",
			Description: "Send a custom HTTP request with full control over method, headers, and body.",
			Example:     exHTTPRequest,
			MakeHandler: func(vm *sobek.Runtime, opts APIOptions) func(sobek.FunctionCall) sobek.Value {
				return func(call sobek.FunctionCall) sobek.Value {
					optsVal := call.Argument(0)
					if sobek.IsUndefined(optsVal) || sobek.IsNull(optsVal) {
						return sobek.Undefined()
					}
					o := optsVal.ToObject(vm)

					method := "GET"
					if v := o.Get("method"); v != nil && !sobek.IsUndefined(v) {
						method = strings.ToUpper(v.String())
					}
					urlStr := ""
					if v := o.Get("url"); v != nil && !sobek.IsUndefined(v) {
						urlStr = v.String()
					}
					body := ""
					if v := o.Get("body"); v != nil && !sobek.IsUndefined(v) {
						body = v.String()
					}

					headers := headersArg(vm, o.Get("headers"))

					return doRequest(vm, opts.HTTPClient, method, urlStr, body, headers)
				}
			},
		},
		{
			Namespace:   NsHTTP,
			Name:        "send",
			Effect:      EffectNetwork,
			Category:    CatHTTP,
			Signature:   ".send(rawRequest: string)",
			Returns:     "{status, headers, body, raw}",
			Description: "Send a raw HTTP request string (as built by insertion.buildRequest).",
			Example:     exHTTPSend,
			MakeHandler: func(vm *sobek.Runtime, opts APIOptions) func(sobek.FunctionCall) sobek.Value {
				return func(call sobek.FunctionCall) sobek.Value {
					rawReq := call.Argument(0).String()
					return doRawRequest(vm, opts.HTTPClient, rawReq)
				}
			},
		},
		{
			Namespace:   NsHTTP,
			Name:        "buildRequest",
			Effect:      EffectPure,
			Category:    CatHTTP,
			Signature:   ".buildRequest(rawRequest: string, overrides: {method?, path?, headers?, body?, query?})",
			Returns:     "string",
			Description: "Modify a raw HTTP request string with the given overrides.",
			Example:     "",
			MakeHandler: func(vm *sobek.Runtime, opts APIOptions) func(sobek.FunctionCall) sobek.Value {
				return func(call sobek.FunctionCall) sobek.Value {
					rawReq := call.Argument(0).String()
					overridesVal := call.Argument(1)
					if sobek.IsUndefined(overridesVal) || sobek.IsNull(overridesVal) {
						return vm.ToValue(rawReq)
					}
					return vm.ToValue(applyRequestOverrides(vm, rawReq, overridesVal.ToObject(vm)))
				}
			},
		},
	}
}

func doSimpleRequest(vm *sobek.Runtime, httpClient *http.Requester, method, urlStr, body string, optsVal sobek.Value) sobek.Value {
	var headersVal sobek.Value
	if optsVal != nil && !sobek.IsUndefined(optsVal) && !sobek.IsNull(optsVal) {
		headersVal = optsVal.ToObject(vm).Get("headers")
	}
	return doRequest(vm, httpClient, method, urlStr, body, headersArg(vm, headersVal))
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

	if body != "" && !mapHasHeader(headers, "Content-Length") {
		fmt.Fprintf(&sb, "Content-Length: %d\r\n", len(body))
	}
	sb.WriteString("\r\n")
	if body != "" {
		sb.WriteString(body)
	}

	return doRawRequestTo(vm, httpClient, sb.String(), urlStr)
}

func doRawRequest(vm *sobek.Runtime, httpClient *http.Requester, rawReq string) sobek.Value {
	return doRawRequestTo(vm, httpClient, rawReq, "")
}

// doRawRequestTo sends rawReq to targetURL's scheme/host/port when known, else
// to the Host header (https for port 443). It used to connect over plain http
// whatever the URL said (NEW-3).
func doRawRequestTo(vm *sobek.Runtime, httpClient *http.Requester, rawReq, targetURL string) sobek.Value {
	req := httpmsg.NewHttpRequest([]byte(rawReq))

	if svc := serviceForRequest(targetURL, req.Header("Host")); svc != nil {
		req = httpmsg.NewHttpRequestWithService(svc, []byte(rawReq))
	}

	hrr := httpmsg.NewHttpRequestResponse(req, nil)

	respChain, elapsed, err := httpClient.Execute(hrr, http.Options{})
	// The requester's own measurement, which starts after rate/host admission —
	// so elapsed_ms reports the target's latency rather than vigolium's queue.
	elapsedMs := elapsed.Milliseconds()

	if err != nil {
		// An offline requester (ext eval without --allow-network) throws, so
		// the extension and its author see why there is no response instead
		// of a silent undefined.
		if errors.Is(err, http.ErrNetworkDisabled) || errors.Is(err, http.ErrHostOutOfScope) {
			panic(vm.NewGoError(err))
		}
		zap.L().Debug("JS HTTP request failed", zap.Error(err))
		return sobek.Undefined()
	}

	fullResp := respChain.FullResponseBytes()
	rawResponseCopy := make([]byte, len(fullResp))
	copy(rawResponseCopy, fullResp)
	respChain.Close()

	httpResp := httpmsg.NewHttpResponseWithDuration(rawResponseCopy, elapsed)

	result := vm.NewObject()
	_ = result.Set("status", httpResp.StatusCode())
	_ = result.Set("body", string(httpResp.Body()))
	_ = result.Set("raw", string(rawResponseCopy))
	_ = result.Set("elapsed_ms", elapsedMs)

	_ = result.Set("headers", newHeadersObject(vm, httpResp.Headers()))

	return result
}

// applyRequestOverrides modifies a raw HTTP request string with the given overrides.
// Supported overrides: method, path, headers (merge), body (replace), query (merge).
func applyRequestOverrides(vm *sobek.Runtime, rawReq string, overrides *sobek.Object) string {
	headerSection, body := parse.SplitHTTPMessage(rawReq)
	lines := parse.SplitHeaderLines(headerSection)
	if len(lines) == 0 {
		return rawReq
	}

	// Parse request line
	parts := strings.Fields(lines[0])
	method := ""
	fullPath := ""
	httpVer := "HTTP/1.1"
	if len(parts) >= 3 {
		method, fullPath, httpVer = parts[0], parts[1], parts[2]
	} else if len(parts) >= 2 {
		method, fullPath = parts[0], parts[1]
	}

	pathOnly, queryStr := parse.SplitPathQuery(fullPath)

	// Apply overrides
	if v := overrides.Get("method"); v != nil && !sobek.IsUndefined(v) {
		method = strings.ToUpper(v.String())
	}
	if v := overrides.Get("path"); v != nil && !sobek.IsUndefined(v) {
		newPath := v.String()
		// If the override path contains a query string, split it
		if idx := strings.IndexByte(newPath, '?'); idx >= 0 {
			pathOnly = newPath[:idx]
			queryStr = newPath[idx+1:]
		} else {
			pathOnly = newPath
		}
	}
	if v := overrides.Get("body"); v != nil && !sobek.IsUndefined(v) {
		body = v.String()
	}

	// Merge query params
	if v := overrides.Get("query"); v != nil && !sobek.IsUndefined(v) {
		existingParams, _ := url.ParseQuery(queryStr)
		queryObj := v.ToObject(vm)
		for _, key := range queryObj.Keys() {
			existingParams.Set(key, queryObj.Get(key).String())
		}
		queryStr = existingParams.Encode()
	}

	// Collect existing headers (preserving order)
	type header struct{ name, value string }
	var headers []header
	for i := 1; i < len(lines); i++ {
		if idx := strings.Index(lines[i], ":"); idx > 0 {
			headers = append(headers, header{
				name:  strings.TrimSpace(lines[i][:idx]),
				value: strings.TrimSpace(lines[i][idx+1:]),
			})
		}
	}

	// Merge override headers
	if v := overrides.Get("headers"); v != nil && !sobek.IsUndefined(v) {
		headersObj := v.ToObject(vm)
		overrideKeys := headersObj.Keys()
		// Build lookup of override header names (case-insensitive)
		overrideLower := make(map[string]string, len(overrideKeys))
		for _, key := range overrideKeys {
			overrideLower[strings.ToLower(key)] = key
		}
		// Update existing headers in place
		for i, h := range headers {
			if origKey, ok := overrideLower[strings.ToLower(h.name)]; ok {
				headers[i].value = headersObj.Get(origKey).String()
				delete(overrideLower, strings.ToLower(h.name))
			}
		}
		// Append new headers
		for _, key := range overrideKeys {
			if _, remaining := overrideLower[strings.ToLower(key)]; remaining {
				headers = append(headers, header{name: key, value: headersObj.Get(key).String()})
			}
		}
	}

	// Rebuild request
	var sb strings.Builder
	reqPath := pathOnly
	if queryStr != "" {
		reqPath += "?" + queryStr
	}
	fmt.Fprintf(&sb, "%s %s %s\r\n", method, reqPath, httpVer)
	for _, h := range headers {
		fmt.Fprintf(&sb, "%s: %s\r\n", h.name, h.value)
	}
	sb.WriteString("\r\n")
	if body != "" {
		sb.WriteString(body)
	}
	return sb.String()
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

// serviceForRequest is the connection target for an extension request: the
// URL's scheme, host and port when targetURL is absolute, else the Host
// header with https for port 443 and http otherwise.
func serviceForRequest(targetURL, hostHeader string) *httpmsg.Service {
	if u, err := url.Parse(targetURL); err == nil && u.Scheme != "" && u.Host != "" {
		if svc, err := httpmsg.ParseService(u.Scheme + "://" + u.Host); err == nil {
			return svc
		}
	}
	if hostHeader == "" {
		return nil
	}
	scheme := "http"
	if _, port, err := net.SplitHostPort(hostHeader); err == nil && port == "443" {
		scheme = "https"
	}
	svc, err := httpmsg.ParseService(scheme + "://" + hostHeader)
	if err != nil {
		return nil
	}
	return svc
}
