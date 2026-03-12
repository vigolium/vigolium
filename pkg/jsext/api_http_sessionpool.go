package jsext

import (
	"fmt"
	"strings"
	"sync"

	"github.com/grafana/sobek"
	gohttp "github.com/vigolium/vigolium/pkg/http"
	"go.uber.org/zap"
)

// httpSessionPoolFuncDefs returns JSFuncDefs for the sessionPool function.
func httpSessionPoolFuncDefs() []JSFuncDef {
	return []JSFuncDef{
		{
			Namespace:   NsHTTP,
			Name:        "sessionPool",
			Category:    CatHTTP,
			Signature:   ".sessionPool(configs: Record<string, LoginOptions | SessionOptions | {}>)",
			Returns:     "SessionPool",
			Description: "Create a pool of named HTTP sessions from login or header configurations.",
			Example:     "",
			MakeHandler: func(vm *sobek.Runtime, opts APIOptions) func(sobek.FunctionCall) sobek.Value {
				return func(call sobek.FunctionCall) sobek.Value {
					configsVal := call.Argument(0)
					if sobek.IsUndefined(configsVal) || sobek.IsNull(configsVal) {
						return vm.NewObject()
					}
					configsObj := configsVal.ToObject(vm)
					names := configsObj.Keys()
					if len(names) == 0 {
						return vm.NewObject()
					}

					httpClient := opts.HTTPClient

					// We need access to the http.login function via the HTTP namespace
					// to reuse login logic for LoginOptions configs.
					vigoliumObj := vm.Get("vigolium")
					var httpNsObj *sobek.Object
					if vigoliumObj != nil && !sobek.IsUndefined(vigoliumObj) {
						httpVal := vigoliumObj.ToObject(vm).Get("http")
						if httpVal != nil && !sobek.IsUndefined(httpVal) {
							httpNsObj = httpVal.ToObject(vm)
						}
					}

					// Store name -> jsSession
					sessions := make(map[string]*jsSession, len(names))
					sessionObjs := make(map[string]sobek.Value, len(names))

					for _, name := range names {
						cfgVal := configsObj.Get(name)
						if sobek.IsUndefined(cfgVal) || sobek.IsNull(cfgVal) {
							// Empty config = unauthenticated session
							sess := newJSSession(vm, httpClient, nil, nil)
							sessions[name] = sess
							obj := sess.toJSObject().ToObject(vm)
							registerInterceptorsOnSession(vm, obj, sess)
							registerCloneOnSession(vm, obj, sess, httpClient)
							sessionObjs[name] = obj
							continue
						}
						cfg := cfgVal.ToObject(vm)

						// Check if this is a LoginOptions (has url + extract)
						hasURL := false
						if v := cfg.Get("url"); v != nil && !sobek.IsUndefined(v) && v.String() != "" {
							hasURL = true
						}
						hasExtract := false
						if v := cfg.Get("extract"); v != nil && !sobek.IsUndefined(v) {
							hasExtract = true
						}

						if hasURL && hasExtract {
							// Treat as LoginOptions -- reuse the http.login logic
							if httpNsObj == nil {
								zap.L().Debug("sessionPool: http namespace not available for login")
								continue
							}
							loginFn, ok := sobek.AssertFunction(httpNsObj.Get("login"))
							if !ok {
								zap.L().Debug("sessionPool: login function not available")
								continue
							}
							sessVal, err := loginFn(sobek.Undefined(), cfgVal)
							if err != nil || sobek.IsUndefined(sessVal) || sobek.IsNull(sessVal) {
								zap.L().Debug("sessionPool: login failed for session", zap.String("name", name))
								// Create empty session as fallback
								sess := newJSSession(vm, httpClient, nil, nil)
								sessions[name] = sess
								obj := sess.toJSObject().ToObject(vm)
								registerInterceptorsOnSession(vm, obj, sess)
								registerCloneOnSession(vm, obj, sess, httpClient)
								sessionObjs[name] = obj
								continue
							}
							// Store the JS object directly and register cloneAs
							sessionObjs[name] = sessVal
							sessObj := sessVal.ToObject(vm)
							registerCloneOnLoginSession(vm, sessObj, httpClient)
							continue
						}

						// Treat as SessionOptions (headers/cookies)
						var headers map[string]string
						var cookies map[string]string

						if v := cfg.Get("headers"); v != nil && !sobek.IsUndefined(v) {
							headers = make(map[string]string)
							headersObj := v.ToObject(vm)
							for _, key := range headersObj.Keys() {
								headers[key] = headersObj.Get(key).String()
							}
						}
						if v := cfg.Get("cookies"); v != nil && !sobek.IsUndefined(v) {
							cookies = make(map[string]string)
							cookiesObj := v.ToObject(vm)
							for _, key := range cookiesObj.Keys() {
								cookies[key] = cookiesObj.Get(key).String()
							}
						}

						sess := newJSSession(vm, httpClient, headers, cookies)
						sessions[name] = sess
						obj := sess.toJSObject().ToObject(vm)
						registerInterceptorsOnSession(vm, obj, sess)
						registerCloneOnSession(vm, obj, sess, httpClient)
						sessionObjs[name] = obj
					}

					// Build SessionPool object
					pool := vm.NewObject()

					// pool.get(name) -> HttpSession
					_ = pool.Set("get", func(call sobek.FunctionCall) sobek.Value {
						name := call.Argument(0).String()
						if sessVal, ok := sessionObjs[name]; ok {
							return sessVal
						}
						return sobek.Undefined()
					})

					// pool.names() -> string[]
					_ = pool.Set("names", func(call sobek.FunctionCall) sobek.Value {
						result := make([]interface{}, 0, len(names))
						for _, name := range names {
							if _, ok := sessionObjs[name]; ok {
								result = append(result, name)
							}
						}
						return vm.ToValue(result)
					})

					// pool.forEach(fn) -> void
					_ = pool.Set("forEach", func(call sobek.FunctionCall) sobek.Value {
						fn, ok := sobek.AssertFunction(call.Argument(0))
						if !ok {
							return sobek.Undefined()
						}
						for _, name := range names {
							if sessVal, ok := sessionObjs[name]; ok {
								_, _ = fn(sobek.Undefined(), vm.ToValue(name), sessVal)
							}
						}
						return sobek.Undefined()
					})

					// pool.broadcast(request) -> Record<string, HttpResponse>
					// Sends the same request through all sessions concurrently
					_ = pool.Set("broadcast", func(call sobek.FunctionCall) sobek.Value {
						reqVal := call.Argument(0)
						if sobek.IsUndefined(reqVal) || sobek.IsNull(reqVal) {
							return vm.NewObject()
						}

						// Determine if it's a string (raw request) or object (FullRequestOptions)
						isRaw := false
						rawReq := ""
						var reqMethod, reqURL, reqBody string
						reqHeaders := make(map[string]string)

						if _, ok := reqVal.Export().(string); ok {
							isRaw = true
							rawReq = reqVal.String()
						} else {
							reqObj := reqVal.ToObject(vm)
							reqMethod = "GET"
							if v := reqObj.Get("method"); v != nil && !sobek.IsUndefined(v) {
								reqMethod = strings.ToUpper(v.String())
							}
							if v := reqObj.Get("url"); v != nil && !sobek.IsUndefined(v) {
								reqURL = v.String()
							}
							if v := reqObj.Get("body"); v != nil && !sobek.IsUndefined(v) {
								reqBody = v.String()
							}
							if v := reqObj.Get("headers"); v != nil && !sobek.IsUndefined(v) {
								hObj := v.ToObject(vm)
								for _, key := range hObj.Keys() {
									reqHeaders[key] = hObj.Get(key).String()
								}
							}
						}

						// Extract session headers on the main goroutine (sobek is not goroutine-safe).
						// We must call JS functions here before launching concurrent goroutines.
						type sessionReq struct {
							name   string
							rawReq string
						}
						preparedReqs := make([]sessionReq, 0, len(sessionObjs))

						for name, sessVal := range sessionObjs {
							sessObj := sessVal.ToObject(vm)
							sessHeaders := extractSessionHeadersMap(vm, sessObj)

							var finalRaw string
							if isRaw {
								// Inject session headers into raw request
								finalRaw = injectHeadersIntoRaw(rawReq, sessHeaders)
							} else {
								// Build request with merged headers
								merged := make(map[string]string)
								for k, v := range sessHeaders {
									merged[k] = v
								}
								for k, v := range reqHeaders {
									merged[k] = v
								}
								var sb strings.Builder
								fmt.Fprintf(&sb, "%s %s HTTP/1.1\r\n", reqMethod, reqURL)
								host := extractHost(reqURL)
								fmt.Fprintf(&sb, "Host: %s\r\n", host)
								for k, v := range merged {
									if strings.EqualFold(k, "host") {
										continue
									}
									fmt.Fprintf(&sb, "%s: %s\r\n", k, v)
								}
								if reqBody != "" && merged["Content-Length"] == "" {
									fmt.Fprintf(&sb, "Content-Length: %d\r\n", len(reqBody))
								}
								sb.WriteString("\r\n")
								if reqBody != "" {
									sb.WriteString(reqBody)
								}
								finalRaw = sb.String()
							}

							preparedReqs = append(preparedReqs, sessionReq{name: name, rawReq: finalRaw})
						}

						// Send through each session concurrently (no VM access in goroutines)
						type broadcastResult struct {
							name string
							resp respSlot
						}
						results := make([]broadcastResult, len(preparedReqs))
						var wg sync.WaitGroup

						for i, pr := range preparedReqs {
							wg.Add(1)
							go func(idx int, req sessionReq) {
								defer wg.Done()
								resp := doRawRequestBytes(httpClient, req.rawReq)
								results[idx] = broadcastResult{name: req.name, resp: resp}
							}(i, pr)
						}
						wg.Wait()

						// Build result object
						resultObj := vm.NewObject()
						for _, br := range results {
							if br.resp.err {
								_ = resultObj.Set(br.name, sobek.Undefined())
							} else {
								_ = resultObj.Set(br.name, buildResponseObject(vm, br.resp.raw, br.resp.elapsed))
							}
						}
						return resultObj
					})

					return pool
				}
			},
		},
	}
}

// extractSessionHeadersMap extracts all default headers from a session JS object as a Go map.
func extractSessionHeadersMap(vm *sobek.Runtime, sessObj *sobek.Object) map[string]string {
	getHeadersFn, ok := sobek.AssertFunction(sessObj.Get("getHeaders"))
	if !ok {
		return nil
	}
	headersVal, err := getHeadersFn(sessObj)
	if err != nil || sobek.IsUndefined(headersVal) || sobek.IsNull(headersVal) {
		return nil
	}
	headersObj := headersVal.ToObject(vm)
	keys := headersObj.Keys()
	result := make(map[string]string, len(keys))
	for _, key := range keys {
		result[key] = headersObj.Get(key).String()
	}
	return result
}

// injectHeadersIntoRaw injects a Go map of headers into a raw HTTP request string.
func injectHeadersIntoRaw(rawReq string, headers map[string]string) string {
	if len(headers) == 0 {
		return rawReq
	}

	headerSection, body := splitHTTPMessage(rawReq)
	lines := splitHeaderLines(headerSection)
	if len(lines) == 0 {
		return rawReq
	}

	overrides := make(map[string]string, len(headers))
	for k, v := range headers {
		overrides[strings.ToLower(k)] = v
	}

	var sb strings.Builder
	sb.WriteString(lines[0])
	sb.WriteString("\r\n")

	applied := make(map[string]bool)
	for _, line := range lines[1:] {
		if idx := strings.IndexByte(line, ':'); idx > 0 {
			name := strings.TrimSpace(line[:idx])
			lower := strings.ToLower(name)
			if val, ok := overrides[lower]; ok {
				fmt.Fprintf(&sb, "%s: %s\r\n", name, val)
				applied[lower] = true
				continue
			}
		}
		sb.WriteString(line)
		sb.WriteString("\r\n")
	}

	// Add new headers
	for k, v := range headers {
		lower := strings.ToLower(k)
		if !applied[lower] && !strings.EqualFold(k, "host") {
			fmt.Fprintf(&sb, "%s: %s\r\n", k, v)
		}
	}

	sb.WriteString("\r\n")
	if body != "" {
		sb.WriteString(body)
	}
	return sb.String()
}

// registerCloneOnSession adds cloneAs() to a session JS object.
func registerCloneOnSession(vm *sobek.Runtime, obj *sobek.Object, sess *jsSession, httpClient *gohttp.Requester) {
	_ = obj.Set("cloneAs", func(call sobek.FunctionCall) sobek.Value {
		// Clone headers
		clonedHeaders := make(map[string]string, len(sess.defaultHeaders))
		for k, v := range sess.defaultHeaders {
			clonedHeaders[k] = v
		}

		cloned := newJSSession(vm, httpClient, clonedHeaders, nil)
		clonedObj := cloned.toJSObject().ToObject(vm)
		registerInterceptorsOnSession(vm, clonedObj, cloned)
		registerCloneOnSession(vm, clonedObj, cloned, httpClient)
		return clonedObj
	})
}

// registerCloneOnLoginSession adds cloneAs() to a session created via http.login().
func registerCloneOnLoginSession(vm *sobek.Runtime, obj *sobek.Object, httpClient *gohttp.Requester) {
	_ = obj.Set("cloneAs", func(call sobek.FunctionCall) sobek.Value {
		// Extract current headers from the session
		headers := extractSessionHeadersMap(vm, obj)
		clonedHeaders := make(map[string]string, len(headers))
		for k, v := range headers {
			clonedHeaders[k] = v
		}

		cloned := newJSSession(vm, httpClient, clonedHeaders, nil)
		clonedObj := cloned.toJSObject().ToObject(vm)
		registerInterceptorsOnSession(vm, clonedObj, cloned)
		registerCloneOnSession(vm, clonedObj, cloned, httpClient)
		return clonedObj
	})
}
