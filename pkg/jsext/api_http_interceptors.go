package jsext

import (
	"fmt"
	"strings"

	"github.com/grafana/sobek"
	"go.uber.org/zap"
)

// interceptorSession wraps jsSession with request/response interceptors.
type interceptorSession struct {
	*jsSession

	onRequestFn  sobek.Callable
	onResponseFn sobek.Callable

	// Auto-refresh config
	autoRefreshTrigger    int
	autoRefreshFn         sobek.Callable
	autoRefreshHeader     string
	autoRefreshMaxRetries int
}

// registerInterceptorsOnSession adds onRequest, onResponse, setAutoRefresh methods to a session JS object.
// This modifies the existing session object in-place.
func registerInterceptorsOnSession(vm *sobek.Runtime, obj *sobek.Object, sess *jsSession) {
	is := &interceptorSession{
		jsSession:             sess,
		autoRefreshMaxRetries: 1,
	}

	// Wrap existing methods to add interceptor support
	wrapSessionMethods(vm, obj, is)

	// vigolium.http.session().onRequest(fn) -> void
	_ = obj.Set("onRequest", func(call sobek.FunctionCall) sobek.Value {
		fn, ok := sobek.AssertFunction(call.Argument(0))
		if !ok {
			zap.L().Debug("session.onRequest: argument must be a function")
			return sobek.Undefined()
		}
		is.onRequestFn = fn
		return sobek.Undefined()
	})

	// vigolium.http.session().onResponse(fn) -> void
	_ = obj.Set("onResponse", func(call sobek.FunctionCall) sobek.Value {
		fn, ok := sobek.AssertFunction(call.Argument(0))
		if !ok {
			zap.L().Debug("session.onResponse: argument must be a function")
			return sobek.Undefined()
		}
		is.onResponseFn = fn
		return sobek.Undefined()
	})

	// vigolium.http.session().setAutoRefresh(opts) -> void
	_ = obj.Set("setAutoRefresh", func(call sobek.FunctionCall) sobek.Value {
		optsVal := call.Argument(0)
		if sobek.IsUndefined(optsVal) || sobek.IsNull(optsVal) {
			return sobek.Undefined()
		}
		opts := optsVal.ToObject(vm)

		if v := opts.Get("trigger"); v != nil && !sobek.IsUndefined(v) {
			is.autoRefreshTrigger = int(v.ToInteger())
		}
		if v := opts.Get("refresh"); v != nil && !sobek.IsUndefined(v) {
			fn, ok := sobek.AssertFunction(v)
			if ok {
				is.autoRefreshFn = fn
			}
		}
		if v := opts.Get("header"); v != nil && !sobek.IsUndefined(v) {
			is.autoRefreshHeader = v.String()
		}
		if v := opts.Get("maxRetries"); v != nil && !sobek.IsUndefined(v) {
			mr := int(v.ToInteger())
			if mr > 0 {
				is.autoRefreshMaxRetries = mr
			}
		}

		return sobek.Undefined()
	})
}

// wrapSessionMethods replaces get/post/request/send with interceptor-aware versions.
func wrapSessionMethods(vm *sobek.Runtime, obj *sobek.Object, is *interceptorSession) {
	_ = obj.Set("get", func(call sobek.FunctionCall) sobek.Value {
		urlStr := call.Argument(0).String()
		headers := is.extractCallHeaders(call.Argument(1))
		return is.doInterceptedHTTP(vm, "GET", urlStr, "", headers)
	})

	_ = obj.Set("post", func(call sobek.FunctionCall) sobek.Value {
		urlStr := call.Argument(0).String()
		body := call.Argument(1).String()
		headers := is.extractCallHeaders(call.Argument(2))
		return is.doInterceptedHTTP(vm, "POST", urlStr, body, headers)
	})

	_ = obj.Set("request", func(call sobek.FunctionCall) sobek.Value {
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
		return is.doInterceptedHTTP(vm, method, urlStr, body, headers)
	})

	_ = obj.Set("send", func(call sobek.FunctionCall) sobek.Value {
		rawReq := call.Argument(0).String()
		return is.doInterceptedRaw(vm, rawReq)
	})
}

// doInterceptedHTTP handles the full interceptor lifecycle for structured requests.
func (is *interceptorSession) doInterceptedHTTP(vm *sobek.Runtime, method, urlStr, body string, headers map[string]string) sobek.Value {
	// Run onRequest interceptor
	if is.onRequestFn != nil {
		reqInfo := vm.NewObject()
		_ = reqInfo.Set("method", method)
		_ = reqInfo.Set("url", urlStr)
		_ = reqInfo.Set("body", body)
		headersObj := vm.NewObject()
		for k, v := range headers {
			_ = headersObj.Set(k, v)
		}
		_ = reqInfo.Set("headers", headersObj)

		result, err := is.onRequestFn(sobek.Undefined(), reqInfo)
		if err == nil && result != nil && !sobek.IsUndefined(result) && !sobek.IsNull(result) {
			// Interceptor returned a modified request
			modObj := result.ToObject(vm)
			if v := modObj.Get("method"); v != nil && !sobek.IsUndefined(v) {
				method = strings.ToUpper(v.String())
			}
			if v := modObj.Get("url"); v != nil && !sobek.IsUndefined(v) {
				urlStr = v.String()
			}
			if v := modObj.Get("body"); v != nil && !sobek.IsUndefined(v) {
				body = v.String()
			}
			if v := modObj.Get("headers"); v != nil && !sobek.IsUndefined(v) {
				headers = make(map[string]string)
				hObj := v.ToObject(vm)
				for _, key := range hObj.Keys() {
					headers[key] = hObj.Get(key).String()
				}
			}
		}
	}

	resp := is.doSessionHTTP(method, urlStr, body, headers)

	// Run onResponse interceptor
	if is.onResponseFn != nil {
		reqInfo := vm.NewObject()
		_ = reqInfo.Set("method", method)
		_ = reqInfo.Set("url", urlStr)
		_, _ = is.onResponseFn(sobek.Undefined(), resp, reqInfo)
	}

	// Auto-refresh on trigger status
	resp = is.handleAutoRefresh(vm, resp, func() sobek.Value {
		return is.doSessionHTTP(method, urlStr, body, headers)
	})

	return resp
}

// doInterceptedRaw handles the full interceptor lifecycle for raw requests.
func (is *interceptorSession) doInterceptedRaw(vm *sobek.Runtime, rawReq string) sobek.Value {
	// For raw requests, onRequest gets the raw string
	if is.onRequestFn != nil {
		reqInfo := vm.NewObject()
		_ = reqInfo.Set("raw", rawReq)
		result, err := is.onRequestFn(sobek.Undefined(), reqInfo)
		if err == nil && result != nil && !sobek.IsUndefined(result) && !sobek.IsNull(result) {
			if v := result.ToObject(vm).Get("raw"); v != nil && !sobek.IsUndefined(v) {
				rawReq = v.String()
			}
		}
	}

	resp := is.doSessionRawRequest(rawReq)

	// Run onResponse interceptor
	if is.onResponseFn != nil {
		reqInfo := vm.NewObject()
		_ = reqInfo.Set("raw", rawReq)
		_, _ = is.onResponseFn(sobek.Undefined(), resp, reqInfo)
	}

	// Auto-refresh
	resp = is.handleAutoRefresh(vm, resp, func() sobek.Value {
		return is.doSessionRawRequest(rawReq)
	})

	return resp
}

// handleAutoRefresh checks if the response status matches the trigger and performs token refresh + retry.
func (is *interceptorSession) handleAutoRefresh(vm *sobek.Runtime, resp sobek.Value, retry func() sobek.Value) sobek.Value {
	if is.autoRefreshFn == nil || is.autoRefreshTrigger == 0 {
		return resp
	}

	if sobek.IsUndefined(resp) || sobek.IsNull(resp) {
		return resp
	}

	for attempt := range is.autoRefreshMaxRetries {
		_ = attempt
		respObj := resp.ToObject(vm)
		statusVal := respObj.Get("status")
		if statusVal == nil || sobek.IsUndefined(statusVal) {
			break
		}

		status := int(statusVal.ToInteger())
		if status != is.autoRefreshTrigger {
			break // Not a trigger status, no refresh needed
		}

		// Call the refresh function to get a new token
		newTokenVal, err := is.autoRefreshFn(sobek.Undefined())
		if err != nil {
			zap.L().Debug("session.autoRefresh: refresh function failed", zap.Error(err))
			break
		}

		newToken := newTokenVal.String()
		if newToken == "" {
			break
		}

		// Apply the new token to the session header
		if is.autoRefreshHeader != "" {
			is.defaultHeaders[is.autoRefreshHeader] = newToken
		} else {
			is.defaultHeaders["Authorization"] = fmt.Sprintf("Bearer %s", newToken)
		}

		// Retry the request
		resp = retry()
	}

	return resp
}
