package jsext

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/grafana/sobek"
	gohttp "github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"go.uber.org/zap"
	"golang.org/x/net/publicsuffix"
)

// jsSession holds persistent state for a JS HTTP session.
type jsSession struct {
	jar            *cookiejar.Jar
	defaultHeaders map[string]string
	httpClient     *gohttp.Requester
	vm             *sobek.Runtime
}

// newJSSession creates a new session with an empty cookie jar and optional default headers/cookies.
func newJSSession(vm *sobek.Runtime, httpClient *gohttp.Requester, headers map[string]string, cookies map[string]string) *jsSession {
	jar, _ := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})

	if headers == nil {
		headers = make(map[string]string)
	}

	// Seed initial cookies into the Cookie header (they'll be applied per-request)
	if len(cookies) > 0 {
		parts := make([]string, 0, len(cookies))
		for k, v := range cookies {
			parts = append(parts, k+"="+v)
		}
		if existing, ok := headers["Cookie"]; ok && existing != "" {
			headers["Cookie"] = existing + "; " + strings.Join(parts, "; ")
		} else {
			headers["Cookie"] = strings.Join(parts, "; ")
		}
	}

	return &jsSession{
		jar:            jar,
		defaultHeaders: headers,
		httpClient:     httpClient,
		vm:             vm,
	}
}

// toJSObject returns a sobek object with get/post/request/send/setHeader/removeHeader/getCookies/setCookie/getHeaders methods.
func (s *jsSession) toJSObject() sobek.Value {
	obj := s.vm.NewObject()

	_ = obj.Set("get", func(call sobek.FunctionCall) sobek.Value {
		urlStr := call.Argument(0).String()
		headers := s.extractCallHeaders(call.Argument(1))
		return s.doSessionHTTP("GET", urlStr, "", headers)
	})

	_ = obj.Set("post", func(call sobek.FunctionCall) sobek.Value {
		urlStr := call.Argument(0).String()
		body := call.Argument(1).String()
		headers := s.extractCallHeaders(call.Argument(2))
		return s.doSessionHTTP("POST", urlStr, body, headers)
	})

	_ = obj.Set("request", func(call sobek.FunctionCall) sobek.Value {
		optsVal := call.Argument(0)
		if sobek.IsUndefined(optsVal) || sobek.IsNull(optsVal) {
			return sobek.Undefined()
		}
		opts := optsVal.ToObject(s.vm)

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
			headersObj := v.ToObject(s.vm)
			for _, key := range headersObj.Keys() {
				headers[key] = headersObj.Get(key).String()
			}
		}
		return s.doSessionHTTP(method, urlStr, body, headers)
	})

	_ = obj.Set("send", func(call sobek.FunctionCall) sobek.Value {
		rawReq := call.Argument(0).String()
		return s.doSessionRawRequest(rawReq)
	})

	_ = obj.Set("setHeader", func(call sobek.FunctionCall) sobek.Value {
		name := call.Argument(0).String()
		value := call.Argument(1).String()
		s.defaultHeaders[name] = value
		return sobek.Undefined()
	})

	_ = obj.Set("removeHeader", func(call sobek.FunctionCall) sobek.Value {
		name := call.Argument(0).String()
		// Case-insensitive removal
		for k := range s.defaultHeaders {
			if strings.EqualFold(k, name) {
				delete(s.defaultHeaders, k)
			}
		}
		return sobek.Undefined()
	})

	_ = obj.Set("getHeaders", func(call sobek.FunctionCall) sobek.Value {
		headersObj := s.vm.NewObject()
		for k, v := range s.defaultHeaders {
			_ = headersObj.Set(k, v)
		}
		return headersObj
	})

	_ = obj.Set("getCookies", func(call sobek.FunctionCall) sobek.Value {
		cookiesObj := s.vm.NewObject()
		// Extract from Cookie header
		if cookieStr, ok := s.defaultHeaders["Cookie"]; ok {
			for _, pair := range strings.Split(cookieStr, ";") {
				pair = strings.TrimSpace(pair)
				if idx := strings.IndexByte(pair, '='); idx > 0 {
					_ = cookiesObj.Set(pair[:idx], pair[idx+1:])
				}
			}
		}
		return cookiesObj
	})

	_ = obj.Set("setCookie", func(call sobek.FunctionCall) sobek.Value {
		name := call.Argument(0).String()
		value := call.Argument(1).String()
		pair := name + "=" + value
		if existing, ok := s.defaultHeaders["Cookie"]; ok && existing != "" {
			// Replace if exists, append if not
			replaced := false
			parts := strings.Split(existing, ";")
			for i, p := range parts {
				p = strings.TrimSpace(p)
				if idx := strings.IndexByte(p, '='); idx > 0 && p[:idx] == name {
					parts[i] = " " + pair
					replaced = true
					break
				}
			}
			if replaced {
				s.defaultHeaders["Cookie"] = strings.TrimSpace(strings.Join(parts, ";"))
			} else {
				s.defaultHeaders["Cookie"] = existing + "; " + pair
			}
		} else {
			s.defaultHeaders["Cookie"] = pair
		}
		return sobek.Undefined()
	})

	return obj
}

// extractCallHeaders extracts a headers map from an optional opts argument.
func (s *jsSession) extractCallHeaders(optsVal sobek.Value) map[string]string {
	headers := make(map[string]string)
	if optsVal != nil && !sobek.IsUndefined(optsVal) && !sobek.IsNull(optsVal) {
		opts := optsVal.ToObject(s.vm)
		if v := opts.Get("headers"); v != nil && !sobek.IsUndefined(v) {
			headersObj := v.ToObject(s.vm)
			for _, key := range headersObj.Keys() {
				headers[key] = headersObj.Get(key).String()
			}
		}
	}
	return headers
}

// doSessionHTTP builds a raw request with session headers merged, sends it, and updates the cookie jar.
func (s *jsSession) doSessionHTTP(method, urlStr, body string, perRequestHeaders map[string]string) sobek.Value {
	// Merge: session defaults → per-request headers (per-request wins)
	merged := make(map[string]string, len(s.defaultHeaders)+len(perRequestHeaders))
	for k, v := range s.defaultHeaders {
		merged[k] = v
	}
	for k, v := range perRequestHeaders {
		merged[k] = v
	}

	// Build raw HTTP request
	var sb strings.Builder
	fmt.Fprintf(&sb, "%s %s HTTP/1.1\r\n", method, urlStr)
	host := extractHost(urlStr)
	fmt.Fprintf(&sb, "Host: %s\r\n", host)
	for k, v := range merged {
		if strings.EqualFold(k, "host") {
			continue
		}
		fmt.Fprintf(&sb, "%s: %s\r\n", k, v)
	}
	if body != "" && merged["Content-Length"] == "" {
		fmt.Fprintf(&sb, "Content-Length: %d\r\n", len(body))
	}
	sb.WriteString("\r\n")
	if body != "" {
		sb.WriteString(body)
	}

	resp := doRawRequest(s.vm, s.httpClient, sb.String())

	// Update cookie jar from Set-Cookie headers in response
	s.updateJarFromResponse(urlStr, resp)

	return resp
}

// doSessionRawRequest injects session headers into a raw request, sends it, and updates the jar.
func (s *jsSession) doSessionRawRequest(rawReq string) sobek.Value {
	// Inject session headers via applyRequestOverrides
	headersObj := s.vm.NewObject()
	for k, v := range s.defaultHeaders {
		_ = headersObj.Set(k, v)
	}
	overrides := s.vm.NewObject()
	_ = overrides.Set("headers", headersObj)
	rawReq = applyRequestOverrides(s.vm, rawReq, overrides)

	resp := doRawRequest(s.vm, s.httpClient, rawReq)

	// Try to extract URL from the raw request for jar update
	urlStr := extractURLFromRaw(rawReq)
	s.updateJarFromResponse(urlStr, resp)

	return resp
}

// updateJarFromResponse parses Set-Cookie headers from a response and updates the jar.
func (s *jsSession) updateJarFromResponse(urlStr string, resp sobek.Value) {
	if sobek.IsUndefined(resp) || sobek.IsNull(resp) {
		return
	}

	respObj := resp.ToObject(s.vm)
	rawVal := respObj.Get("raw")
	if rawVal == nil || sobek.IsUndefined(rawVal) {
		return
	}

	raw := rawVal.String()
	u, err := url.Parse(urlStr)
	if err != nil || u.Host == "" {
		return
	}

	// Parse Set-Cookie headers from raw response
	headerSection, _ := splitHTTPMessage(raw)
	lines := splitHeaderLines(headerSection)
	var setCookies []string
	for _, line := range lines[1:] { // skip status line
		if idx := strings.IndexByte(line, ':'); idx > 0 {
			name := strings.TrimSpace(line[:idx])
			if strings.EqualFold(name, "Set-Cookie") {
				setCookies = append(setCookies, strings.TrimSpace(line[idx+1:]))
			}
		}
	}

	if len(setCookies) == 0 {
		return
	}

	// Build http.Response-compatible cookies and add to jar
	httpResp := &http.Response{Header: make(http.Header)}
	for _, sc := range setCookies {
		httpResp.Header.Add("Set-Cookie", sc)
	}
	cookies := httpResp.Cookies()
	s.jar.SetCookies(u, cookies)

	// Also merge into the default Cookie header for subsequent requests
	jarCookies := s.jar.Cookies(u)
	if len(jarCookies) > 0 {
		parts := make([]string, len(jarCookies))
		for i, c := range jarCookies {
			parts[i] = c.Name + "=" + c.Value
		}
		s.defaultHeaders["Cookie"] = strings.Join(parts, "; ")
	}
}

// extractURLFromRaw tries to reconstruct a URL from a raw HTTP request's request line and Host header.
func extractURLFromRaw(rawReq string) string {
	headerSection, _ := splitHTTPMessage(rawReq)
	lines := splitHeaderLines(headerSection)
	if len(lines) == 0 {
		return ""
	}

	parts := strings.Fields(lines[0])
	path := "/"
	if len(parts) >= 2 {
		path = parts[1]
	}

	// If path is already a full URL, return it
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		return path
	}

	// Find Host header
	host := ""
	for _, line := range lines[1:] {
		if idx := strings.IndexByte(line, ':'); idx > 0 {
			name := strings.TrimSpace(line[:idx])
			if strings.EqualFold(name, "Host") {
				host = strings.TrimSpace(line[idx+1:])
				break
			}
		}
	}
	if host == "" {
		return ""
	}

	return "http://" + host + path
}

// registerHTTPSessionAPIs adds session/login/batch/replay/sequence to the existing httpObj.
func registerHTTPSessionAPIs(vm *sobek.Runtime, httpObj *sobek.Object, httpClient *gohttp.Requester) {
	// vigolium.http.session(opts?) -> Session
	_ = httpObj.Set("session", func(call sobek.FunctionCall) sobek.Value {
		var headers map[string]string
		var cookies map[string]string

		optsVal := call.Argument(0)
		if optsVal != nil && !sobek.IsUndefined(optsVal) && !sobek.IsNull(optsVal) {
			opts := optsVal.ToObject(vm)
			if v := opts.Get("headers"); v != nil && !sobek.IsUndefined(v) {
				headers = make(map[string]string)
				headersObj := v.ToObject(vm)
				for _, key := range headersObj.Keys() {
					headers[key] = headersObj.Get(key).String()
				}
			}
			if v := opts.Get("cookies"); v != nil && !sobek.IsUndefined(v) {
				cookies = make(map[string]string)
				cookiesObj := v.ToObject(vm)
				for _, key := range cookiesObj.Keys() {
					cookies[key] = cookiesObj.Get(key).String()
				}
			}
		}

		sess := newJSSession(vm, httpClient, headers, cookies)
		return sess.toJSObject()
	})

	// vigolium.http.login(opts) -> Session
	_ = httpObj.Set("login", func(call sobek.FunctionCall) sobek.Value {
		optsVal := call.Argument(0)
		if sobek.IsUndefined(optsVal) || sobek.IsNull(optsVal) {
			zap.L().Debug("http.login: missing options")
			return sobek.Undefined()
		}
		opts := optsVal.ToObject(vm)

		loginURL := ""
		if v := opts.Get("url"); v != nil && !sobek.IsUndefined(v) {
			loginURL = v.String()
		}
		if loginURL == "" {
			zap.L().Debug("http.login: url is required")
			return sobek.Undefined()
		}

		method := "POST"
		if v := opts.Get("method"); v != nil && !sobek.IsUndefined(v) {
			method = strings.ToUpper(v.String())
		}

		body := ""
		if v := opts.Get("body"); v != nil && !sobek.IsUndefined(v) {
			body = v.String()
		}

		contentType := ""
		if v := opts.Get("content_type"); v != nil && !sobek.IsUndefined(v) {
			contentType = v.String()
		}
		if contentType == "" && body != "" {
			// Auto-detect
			if strings.HasPrefix(strings.TrimSpace(body), "{") {
				contentType = "application/json"
			} else {
				contentType = "application/x-www-form-urlencoded"
			}
		}

		headers := make(map[string]string)
		if v := opts.Get("headers"); v != nil && !sobek.IsUndefined(v) {
			headersObj := v.ToObject(vm)
			for _, key := range headersObj.Keys() {
				headers[key] = headersObj.Get(key).String()
			}
		}
		if contentType != "" {
			headers["Content-Type"] = contentType
		}

		// Extract rules
		var extractRules []jsExtractRule
		if v := opts.Get("extract"); v != nil && !sobek.IsUndefined(v) {
			rulesArr := v.ToObject(vm)
			length := int(rulesArr.Get("length").ToInteger())
			for i := range length {
				item := rulesArr.Get(fmt.Sprintf("%d", i)).ToObject(vm)
				rule := jsExtractRule{}
				if rv := item.Get("source"); rv != nil && !sobek.IsUndefined(rv) {
					rule.Source = rv.String()
				}
				if rv := item.Get("name"); rv != nil && !sobek.IsUndefined(rv) {
					rule.Name = rv.String()
				}
				if rv := item.Get("path"); rv != nil && !sobek.IsUndefined(rv) {
					rule.Path = rv.String()
				}
				if rv := item.Get("apply_as"); rv != nil && !sobek.IsUndefined(rv) {
					rule.ApplyAs = rv.String()
				}
				extractRules = append(extractRules, rule)
			}
		}

		// Create session and send login request
		sess := newJSSession(vm, httpClient, nil, nil)
		resp := doRequest(vm, httpClient, method, loginURL, body, headers)
		if sobek.IsUndefined(resp) || sobek.IsNull(resp) {
			zap.L().Debug("http.login: login request failed")
			return sobek.Undefined()
		}

		// Update cookie jar from response
		sess.updateJarFromResponse(loginURL, resp)

		// Apply extraction rules
		respObj := resp.ToObject(vm)
		respBody := ""
		if v := respObj.Get("body"); v != nil && !sobek.IsUndefined(v) {
			respBody = v.String()
		}
		respRaw := ""
		if v := respObj.Get("raw"); v != nil && !sobek.IsUndefined(v) {
			respRaw = v.String()
		}
		respHeaders := make(map[string]string)
		if v := respObj.Get("headers"); v != nil && !sobek.IsUndefined(v) {
			headersObj := v.ToObject(vm)
			for _, key := range headersObj.Keys() {
				respHeaders[key] = headersObj.Get(key).String()
			}
		}

		for _, rule := range extractRules {
			value := extractTokenValue(rule, respBody, respRaw, respHeaders)
			if value == "" {
				zap.L().Debug("http.login: extraction returned empty value",
					zap.String("source", rule.Source), zap.String("name", rule.Name))
				continue
			}

			if rule.ApplyAs != "" {
				applySessionHeaderTemplate(sess, rule.ApplyAs, value)
			} else if rule.Source == "cookie" {
				// Append to Cookie header
				pair := rule.Name + "=" + value
				if existing, ok := sess.defaultHeaders["Cookie"]; ok && existing != "" {
					sess.defaultHeaders["Cookie"] = existing + "; " + pair
				} else {
					sess.defaultHeaders["Cookie"] = pair
				}
			} else if rule.Name != "" {
				sess.defaultHeaders[rule.Name] = value
			}
		}

		return sess.toJSObject()
	})

	// vigolium.http.batch(requests, opts?) -> HttpResponse[]
	_ = httpObj.Set("batch", func(call sobek.FunctionCall) sobek.Value {
		reqsVal := call.Argument(0)
		if sobek.IsUndefined(reqsVal) || sobek.IsNull(reqsVal) {
			return vm.NewArray()
		}
		reqsArr := reqsVal.ToObject(vm)
		length := int(reqsArr.Get("length").ToInteger())
		if length == 0 {
			return vm.NewArray()
		}

		concurrency := 5
		if optsVal := call.Argument(1); optsVal != nil && !sobek.IsUndefined(optsVal) && !sobek.IsNull(optsVal) {
			opts := optsVal.ToObject(vm)
			if v := opts.Get("concurrency"); v != nil && !sobek.IsUndefined(v) {
				c := int(v.ToInteger())
				if c > 0 && c <= 20 {
					concurrency = c
				}
			}
		}

		// Parse all requests first (on the VM goroutine)
		type batchReq struct {
			method  string
			urlStr  string
			body    string
			headers map[string]string
		}
		reqs := make([]batchReq, length)
		for i := range length {
			item := reqsArr.Get(fmt.Sprintf("%d", i)).ToObject(vm)
			r := batchReq{method: "GET", headers: make(map[string]string)}
			if v := item.Get("method"); v != nil && !sobek.IsUndefined(v) {
				r.method = strings.ToUpper(v.String())
			}
			if v := item.Get("url"); v != nil && !sobek.IsUndefined(v) {
				r.urlStr = v.String()
			}
			if v := item.Get("body"); v != nil && !sobek.IsUndefined(v) {
				r.body = v.String()
			}
			if v := item.Get("headers"); v != nil && !sobek.IsUndefined(v) {
				headersObj := v.ToObject(vm)
				for _, key := range headersObj.Keys() {
					r.headers[key] = headersObj.Get(key).String()
				}
			}
			reqs[i] = r
		}

		// Build raw requests (on VM goroutine) then send concurrently
		rawReqs := make([]string, length)
		for i, r := range reqs {
			var sb strings.Builder
			fmt.Fprintf(&sb, "%s %s HTTP/1.1\r\n", r.method, r.urlStr)
			host := extractHost(r.urlStr)
			fmt.Fprintf(&sb, "Host: %s\r\n", host)
			for k, v := range r.headers {
				if strings.EqualFold(k, "host") {
					continue
				}
				fmt.Fprintf(&sb, "%s: %s\r\n", k, v)
			}
			if r.body != "" && r.headers["Content-Length"] == "" {
				fmt.Fprintf(&sb, "Content-Length: %d\r\n", len(r.body))
			}
			sb.WriteString("\r\n")
			if r.body != "" {
				sb.WriteString(r.body)
			}
			rawReqs[i] = sb.String()
		}

		// Send concurrently, collect raw response bytes
		slots := make([]respSlot, length)
		sem := make(chan struct{}, concurrency)
		var wg sync.WaitGroup

		for i, rawReq := range rawReqs {
			wg.Add(1)
			go func(idx int, raw string) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				resp := doRawRequestBytes(httpClient, raw)
				slots[idx] = resp
			}(i, rawReq)
		}
		wg.Wait()

		// Build JS response objects back on the VM goroutine
		results := make([]interface{}, length)
		for i, slot := range slots {
			if slot.err {
				results[i] = sobek.Undefined()
				continue
			}
			results[i] = buildResponseObject(vm, slot.raw, slot.elapsed)
		}
		return vm.ToValue(results)
	})

	// vigolium.http.replay(rawRequest, variations) -> HttpResponse[]
	_ = httpObj.Set("replay", func(call sobek.FunctionCall) sobek.Value {
		rawReq := call.Argument(0).String()
		variationsVal := call.Argument(1)
		if sobek.IsUndefined(variationsVal) || sobek.IsNull(variationsVal) {
			return vm.NewArray()
		}
		variationsArr := variationsVal.ToObject(vm)
		length := int(variationsArr.Get("length").ToInteger())
		if length == 0 {
			return vm.NewArray()
		}

		results := make([]interface{}, length)
		for i := range length {
			variation := variationsArr.Get(fmt.Sprintf("%d", i))
			if sobek.IsUndefined(variation) || sobek.IsNull(variation) {
				results[i] = doRawRequest(vm, httpClient, rawReq)
				continue
			}

			overridesObj := variation.ToObject(vm)

			// Handle remove_headers: build a modified overrides that sets removed headers to empty
			if v := overridesObj.Get("remove_headers"); v != nil && !sobek.IsUndefined(v) {
				removeArr := v.ToObject(vm)
				removeLen := int(removeArr.Get("length").ToInteger())
				if removeLen > 0 {
					// We need to strip these headers from the raw request before applying other overrides
					rawReq = removeHeadersFromRaw(rawReq, vm, removeArr, removeLen)
				}
			}

			modifiedReq := applyRequestOverrides(vm, rawReq, overridesObj)
			results[i] = doRawRequest(vm, httpClient, modifiedReq)
		}
		return vm.ToValue(results)
	})

	// vigolium.http.sequence(steps) -> {responses: HttpResponse[], variables: Record<string,string>, success: bool}
	_ = httpObj.Set("sequence", func(call sobek.FunctionCall) sobek.Value {
		stepsVal := call.Argument(0)
		if sobek.IsUndefined(stepsVal) || sobek.IsNull(stepsVal) {
			return sobek.Undefined()
		}
		stepsArr := stepsVal.ToObject(vm)
		length := int(stepsArr.Get("length").ToInteger())
		if length == 0 {
			return sobek.Undefined()
		}

		variables := make(map[string]string)
		responses := make([]interface{}, 0, length)
		success := true

		for i := range length {
			step := stepsArr.Get(fmt.Sprintf("%d", i)).ToObject(vm)

			var resp sobek.Value

			// Check if raw request template is provided
			if v := step.Get("request"); v != nil && !sobek.IsUndefined(v) {
				rawReq := substituteVars(v.String(), variables)
				resp = doRawRequest(vm, httpClient, rawReq)
			} else {
				// Build from method/url/headers/body
				method := "GET"
				if v := step.Get("method"); v != nil && !sobek.IsUndefined(v) {
					method = strings.ToUpper(substituteVars(v.String(), variables))
				}
				urlStr := ""
				if v := step.Get("url"); v != nil && !sobek.IsUndefined(v) {
					urlStr = substituteVars(v.String(), variables)
				}
				body := ""
				if v := step.Get("body"); v != nil && !sobek.IsUndefined(v) {
					body = substituteVars(v.String(), variables)
				}
				headers := make(map[string]string)
				if v := step.Get("headers"); v != nil && !sobek.IsUndefined(v) {
					headersObj := v.ToObject(vm)
					for _, key := range headersObj.Keys() {
						headers[key] = substituteVars(headersObj.Get(key).String(), variables)
					}
				}
				resp = doRequest(vm, httpClient, method, urlStr, body, headers)
			}

			if sobek.IsUndefined(resp) || sobek.IsNull(resp) {
				responses = append(responses, sobek.Undefined())
				success = false
				break
			}

			responses = append(responses, resp)

			// Apply extraction rules
			if v := step.Get("extract"); v != nil && !sobek.IsUndefined(v) {
				respObj := resp.ToObject(vm)
				respBody := ""
				if bv := respObj.Get("body"); bv != nil && !sobek.IsUndefined(bv) {
					respBody = bv.String()
				}
				respRaw := ""
				if rv := respObj.Get("raw"); rv != nil && !sobek.IsUndefined(rv) {
					respRaw = rv.String()
				}
				respHeaders := make(map[string]string)
				if hv := respObj.Get("headers"); hv != nil && !sobek.IsUndefined(hv) {
					headersObj := hv.ToObject(vm)
					for _, key := range headersObj.Keys() {
						respHeaders[key] = headersObj.Get(key).String()
					}
				}

				extractObj := v.ToObject(vm)
				for _, varName := range extractObj.Keys() {
					ruleObj := extractObj.Get(varName).ToObject(vm)
					rule := jsExtractRule{}
					if rv := ruleObj.Get("source"); rv != nil && !sobek.IsUndefined(rv) {
						rule.Source = rv.String()
					}
					if rv := ruleObj.Get("path"); rv != nil && !sobek.IsUndefined(rv) {
						rule.Path = rv.String()
					}
					if rv := ruleObj.Get("name"); rv != nil && !sobek.IsUndefined(rv) {
						rule.Name = rv.String()
					}
					if rv := ruleObj.Get("pattern"); rv != nil && !sobek.IsUndefined(rv) {
						rule.Pattern = rv.String()
					}

					value := extractTokenValue(rule, respBody, respRaw, respHeaders)
					if value != "" {
						variables[varName] = value
					}
				}
			}
		}

		result := vm.NewObject()
		_ = result.Set("responses", vm.ToValue(responses))
		varsObj := vm.NewObject()
		for k, v := range variables {
			_ = varsObj.Set(k, v)
		}
		_ = result.Set("variables", varsObj)
		_ = result.Set("success", success)
		return result
	})
}

// ── Token extraction helpers ─────────────────────────────────────────────────

// jsExtractRule defines how to extract a value from an HTTP response.
type jsExtractRule struct {
	Source  string // "cookie", "json", "header", "regex", "body"
	Name   string // Cookie name or header name
	Path   string // JSON dot-path
	Pattern string // Regex pattern (for regex source)
	ApplyAs string // Header template: "HeaderName: {value}"
}

// extractTokenValue extracts a value from response data according to the rule.
func extractTokenValue(rule jsExtractRule, body, raw string, headers map[string]string) string {
	switch rule.Source {
	case "cookie":
		return extractCookieValue(rule.Name, raw, headers)
	case "json":
		return extractJSONValue(body, rule.Path)
	case "header":
		return extractHeaderValue(rule.Name, headers)
	case "regex":
		return extractRegexValue(body, rule.Pattern)
	case "body":
		return body
	default:
		return ""
	}
}

func extractCookieValue(name, raw string, headers map[string]string) string {
	// Parse Set-Cookie from raw response
	headerSection, _ := splitHTTPMessage(raw)
	lines := splitHeaderLines(headerSection)

	for _, line := range lines {
		if idx := strings.IndexByte(line, ':'); idx > 0 {
			hName := strings.TrimSpace(line[:idx])
			if strings.EqualFold(hName, "Set-Cookie") {
				cookieStr := strings.TrimSpace(line[idx+1:])
				// Parse "name=value; ..."
				if eqIdx := strings.IndexByte(cookieStr, '='); eqIdx > 0 {
					cName := cookieStr[:eqIdx]
					if name == "" || cName == name {
						rest := cookieStr[eqIdx+1:]
						if semiIdx := strings.IndexByte(rest, ';'); semiIdx >= 0 {
							return rest[:semiIdx]
						}
						return rest
					}
				}
			}
		}
	}

	// If no name specified and no Set-Cookie found, return empty
	return ""
}

func extractJSONValue(body, path string) string {
	if path == "" {
		return ""
	}

	var data interface{}
	if err := json.Unmarshal([]byte(body), &data); err != nil {
		return ""
	}

	// Strip leading "$."
	path = strings.TrimPrefix(path, "$.")
	path = strings.TrimPrefix(path, "$")

	result := walkJSONPath(data, path)
	if result == nil {
		return ""
	}
	return fmt.Sprintf("%v", result)
}

func extractHeaderValue(name string, headers map[string]string) string {
	if name == "" {
		return ""
	}
	// Case-insensitive lookup
	for k, v := range headers {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return ""
}

func extractRegexValue(body, pattern string) string {
	if pattern == "" {
		return ""
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return ""
	}
	matches := re.FindStringSubmatch(body)
	if matches == nil {
		return ""
	}
	if len(matches) > 1 {
		return matches[1] // first capture group
	}
	return matches[0]
}

// applySessionHeaderTemplate sets a header on a session from a template like "Authorization: Bearer {value}".
func applySessionHeaderTemplate(sess *jsSession, template, value string) {
	resolved := strings.ReplaceAll(template, "{value}", value)
	parts := strings.SplitN(resolved, ":", 2)
	if len(parts) == 2 && strings.TrimSpace(parts[0]) != "" {
		sess.defaultHeaders[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
	}
}

// substituteVars replaces {{varName}} placeholders in a string.
func substituteVars(s string, vars map[string]string) string {
	for name, value := range vars {
		s = strings.ReplaceAll(s, "{{"+name+"}}", value)
	}
	return s
}

// removeHeadersFromRaw removes specified headers from a raw HTTP request.
func removeHeadersFromRaw(rawReq string, vm *sobek.Runtime, removeArr *sobek.Object, removeLen int) string {
	toRemove := make(map[string]bool, removeLen)
	for i := range removeLen {
		name := removeArr.Get(fmt.Sprintf("%d", i)).String()
		toRemove[strings.ToLower(name)] = true
	}

	headerSection, body := splitHTTPMessage(rawReq)
	lines := splitHeaderLines(headerSection)
	if len(lines) == 0 {
		return rawReq
	}

	var sb strings.Builder
	sb.WriteString(lines[0])
	sb.WriteString("\r\n")
	for _, line := range lines[1:] {
		if idx := strings.IndexByte(line, ':'); idx > 0 {
			name := strings.TrimSpace(line[:idx])
			if toRemove[strings.ToLower(name)] {
				continue // skip this header
			}
		}
		sb.WriteString(line)
		sb.WriteString("\r\n")
	}
	sb.WriteString("\r\n")
	if body != "" {
		sb.WriteString(body)
	}
	return sb.String()
}

// respSlot holds the result of a concurrent HTTP request.
type respSlot struct {
	raw     []byte
	elapsed int64
	err     bool
}

// doRawRequestBytes is like doRawRequest but returns raw bytes for concurrent use (no VM access).
func doRawRequestBytes(httpClient *gohttp.Requester, rawReq string) respSlot {
	req := httpmsg.NewHttpRequest([]byte(rawReq))

	// Infer service from Host header
	if host := req.Header("Host"); host != "" {
		svc, err := httpmsg.ParseService("http://" + host)
		if err == nil {
			req = httpmsg.NewHttpRequestWithService(svc, []byte(rawReq))
		}
	}

	hrr := httpmsg.NewHttpRequestResponse(req, nil)

	start := time.Now()
	respChain, _, err := httpClient.Execute(hrr, gohttp.Options{})
	elapsedMs := time.Since(start).Milliseconds()

	if err != nil {
		zap.L().Debug("JS batch HTTP request failed", zap.Error(err))
		return respSlot{err: true}
	}

	fullResp := respChain.FullResponse().Bytes()
	rawResponseCopy := make([]byte, len(fullResp))
	copy(rawResponseCopy, fullResp)
	respChain.Close()

	return respSlot{raw: rawResponseCopy, elapsed: elapsedMs}
}

// buildResponseObject creates a JS response object from raw bytes.
func buildResponseObject(vm *sobek.Runtime, rawResponse []byte, elapsedMs int64) sobek.Value {
	if len(rawResponse) == 0 {
		return sobek.Undefined()
	}

	httpResp := httpmsg.NewHttpResponse(rawResponse)

	result := vm.NewObject()
	_ = result.Set("status", httpResp.StatusCode())
	_ = result.Set("body", string(httpResp.Body()))
	_ = result.Set("raw", string(rawResponse))
	_ = result.Set("elapsed_ms", elapsedMs)

	headersObj := vm.NewObject()
	for _, h := range httpResp.Headers() {
		_ = headersObj.Set(strings.ToLower(h.Name), h.Value)
	}
	_ = result.Set("headers", headersObj)

	return result
}

// ── registerUtilsTokenAPI adds extractToken to the utils namespace ───────────

func registerUtilsTokenAPI(vm *sobek.Runtime, utilsObj *sobek.Object) {
	// vigolium.utils.extractToken(response, rules) -> Record<string, string>
	_ = utilsObj.Set("extractToken", func(call sobek.FunctionCall) sobek.Value {
		respVal := call.Argument(0)
		rulesVal := call.Argument(1)

		if sobek.IsUndefined(respVal) || sobek.IsNull(respVal) ||
			sobek.IsUndefined(rulesVal) || sobek.IsNull(rulesVal) {
			return vm.NewObject()
		}

		respObj := respVal.ToObject(vm)
		body := ""
		if v := respObj.Get("body"); v != nil && !sobek.IsUndefined(v) {
			body = v.String()
		}
		raw := ""
		if v := respObj.Get("raw"); v != nil && !sobek.IsUndefined(v) {
			raw = v.String()
		}
		headers := make(map[string]string)
		if v := respObj.Get("headers"); v != nil && !sobek.IsUndefined(v) {
			headersObj := v.ToObject(vm)
			for _, key := range headersObj.Keys() {
				headers[key] = headersObj.Get(key).String()
			}
		}

		rulesArr := rulesVal.ToObject(vm)
		length := int(rulesArr.Get("length").ToInteger())

		result := vm.NewObject()
		for i := range length {
			ruleObj := rulesArr.Get(fmt.Sprintf("%d", i)).ToObject(vm)
			rule := jsExtractRule{}
			if v := ruleObj.Get("source"); v != nil && !sobek.IsUndefined(v) {
				rule.Source = v.String()
			}
			if v := ruleObj.Get("name"); v != nil && !sobek.IsUndefined(v) {
				rule.Name = v.String()
			}
			if v := ruleObj.Get("path"); v != nil && !sobek.IsUndefined(v) {
				rule.Path = v.String()
			}
			if v := ruleObj.Get("pattern"); v != nil && !sobek.IsUndefined(v) {
				rule.Pattern = v.String()
			}

			value := extractTokenValue(rule, body, raw, headers)

			// Use name/path as key, fall back to index
			key := rule.Name
			if key == "" {
				key = rule.Path
			}
			if key == "" {
				key = fmt.Sprintf("%d", i)
			}
			_ = result.Set(key, value)
		}

		return result
	})
}
