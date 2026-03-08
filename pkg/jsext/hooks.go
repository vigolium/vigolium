package jsext

import (
	"fmt"

	"github.com/grafana/sobek"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/output"
	"go.uber.org/zap"
)

// PreHookExecutor is the interface for pre-hooks (JS or YAML).
type PreHookExecutor interface {
	ID() string
	Execute(req *httpmsg.HttpRequestResponse) (*httpmsg.HttpRequestResponse, error)
}

// PostHookExecutor is the interface for post-hooks (JS or YAML).
type PostHookExecutor interface {
	ID() string
	Execute(result *output.ResultEvent) (*output.ResultEvent, error)
}

// PreHook transforms or filters requests before modules run.
// No mutex needed — sync.Pool is thread-safe and each VM is an independent runtime.
type PreHook struct {
	script *LoadedScript
	pool   *VMPool
}

// NewPreHook creates a PreHook from a JS script.
func NewPreHook(script *LoadedScript, opts APIOptions) (*PreHook, error) {
	pool, err := NewVMPool(script, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to compile pre-hook script %s: %w", script.Path, err)
	}
	return &PreHook{
		script: script,
		pool:   pool,
	}, nil
}

// ID returns the hook identifier.
func (h *PreHook) ID() string { return h.script.Metadata.ID }

// Execute runs the pre-hook on a request.
// Returns the (possibly modified) request, or nil to skip the item.
func (h *PreHook) Execute(req *httpmsg.HttpRequestResponse) (*httpmsg.HttpRequestResponse, error) {
	vm := h.pool.Get()
	defer h.pool.Put(vm)

	// Build request object
	reqObj := vm.NewObject()
	if req.Request() != nil {
		_ = reqObj.Set("raw", string(req.Request().Raw()))
		_ = reqObj.Set("method", req.Request().Method())
		url := req.Target()
		if url == "" {
			// Fallback to path when service is not set (no full URL available)
			url = req.Request().Path()
		}
		_ = reqObj.Set("url", url)

		headersObj := vm.NewObject()
		for _, hdr := range req.Request().Headers() {
			_ = headersObj.Set(hdr.Name, hdr.Value)
		}
		_ = reqObj.Set("headers", headersObj)
	}

	// Call execute(request)
	exports := vm.Get("module").ToObject(vm).Get("exports").ToObject(vm)
	fn := exports.Get("execute")
	if fn == nil || sobek.IsUndefined(fn) {
		return req, nil
	}

	callable, ok := sobek.AssertFunction(fn)
	if !ok {
		return nil, fmt.Errorf("pre_hook execute is not a function in %s", h.script.Path)
	}

	result, err := callable(exports, reqObj)
	if err != nil {
		return nil, fmt.Errorf("pre_hook JS error in %s: %w", h.script.Path, err)
	}

	// null/undefined means skip this item
	if result == nil || sobek.IsUndefined(result) || sobek.IsNull(result) {
		return nil, nil
	}

	// Check if the hook modified the request
	resultObj := result.ToObject(vm)
	rawVal := resultObj.Get("raw")
	if rawVal != nil && !sobek.IsUndefined(rawVal) {
		// Reconstruct request from modified raw, preserving the original service
		newReq := httpmsg.NewHttpRequestWithService(req.Service(), []byte(rawVal.String()))
		return httpmsg.NewHttpRequestResponse(newReq, req.Response()), nil
	}

	// Check if headers were modified
	headersVal := resultObj.Get("headers")
	if headersVal != nil && !sobek.IsUndefined(headersVal) {
		// Rebuild raw request with modified headers
		headersObj := headersVal.ToObject(vm)
		raw := make([]byte, len(req.Request().Raw()))
		copy(raw, req.Request().Raw())

		for _, key := range headersObj.Keys() {
			val := headersObj.Get(key).String()
			modified, err := httpmsg.AddOrReplaceHeader(raw, key, val)
			if err == nil {
				raw = modified
			}
		}

		newReq := httpmsg.NewHttpRequestWithService(req.Service(), raw)
		return httpmsg.NewHttpRequestResponse(newReq, req.Response()), nil
	}

	return req, nil
}

// PostHook enriches or filters results after modules emit them.
// No mutex needed — sync.Pool is thread-safe and each VM is an independent runtime.
type PostHook struct {
	script *LoadedScript
	pool   *VMPool
}

// NewPostHook creates a PostHook from a JS script.
func NewPostHook(script *LoadedScript, opts APIOptions) (*PostHook, error) {
	pool, err := NewVMPool(script, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to compile post-hook script %s: %w", script.Path, err)
	}
	return &PostHook{
		script: script,
		pool:   pool,
	}, nil
}

// ID returns the hook identifier.
func (h *PostHook) ID() string { return h.script.Metadata.ID }

// Execute runs the post-hook on a result.
// Returns the (possibly modified) result, or nil to drop it.
func (h *PostHook) Execute(result *output.ResultEvent) (*output.ResultEvent, error) {
	vm := h.pool.Get()
	defer h.pool.Put(vm)

	// Build result object
	resultObj := vm.NewObject()
	_ = resultObj.Set("moduleId", result.ModuleID)
	_ = resultObj.Set("templateId", result.ModuleID) // backward compat alias
	_ = resultObj.Set("url", result.URL)
	_ = resultObj.Set("host", result.Host)
	_ = resultObj.Set("matched", result.Matched)
	_ = resultObj.Set("request", result.Request)
	_ = resultObj.Set("response", result.Response)

	infoObj := vm.NewObject()
	_ = infoObj.Set("name", result.Info.Name)
	_ = infoObj.Set("description", result.Info.Description)
	_ = infoObj.Set("severity", result.Info.Severity.String())
	_ = infoObj.Set("confidence", result.Info.Confidence.String())
	_ = resultObj.Set("info", infoObj)

	// Call execute(result)
	exports := vm.Get("module").ToObject(vm).Get("exports").ToObject(vm)
	fn := exports.Get("execute")
	if fn == nil || sobek.IsUndefined(fn) {
		return result, nil
	}

	callable, ok := sobek.AssertFunction(fn)
	if !ok {
		return nil, fmt.Errorf("post_hook execute is not a function in %s", h.script.Path)
	}

	ret, err := callable(exports, resultObj)
	if err != nil {
		return nil, fmt.Errorf("post_hook JS error in %s: %w", h.script.Path, err)
	}

	// null/undefined means drop this result
	if ret == nil || sobek.IsUndefined(ret) || sobek.IsNull(ret) {
		return nil, nil
	}

	// Apply any modifications back
	retObj := ret.ToObject(vm)

	if v := retObj.Get("url"); v != nil && !sobek.IsUndefined(v) {
		result.URL = v.String()
	}
	if v := retObj.Get("matched"); v != nil && !sobek.IsUndefined(v) {
		result.Matched = v.String()
	}

	infoVal := retObj.Get("info")
	if infoVal != nil && !sobek.IsUndefined(infoVal) {
		infoRetObj := infoVal.ToObject(vm)
		if v := infoRetObj.Get("name"); v != nil && !sobek.IsUndefined(v) {
			result.Info.Name = v.String()
		}
		if v := infoRetObj.Get("description"); v != nil && !sobek.IsUndefined(v) {
			result.Info.Description = v.String()
		}
		if v := infoRetObj.Get("severity"); v != nil && !sobek.IsUndefined(v) {
			result.Info.Severity = ParseSeverity(v.String())
		}
	}

	return result, nil
}

// HookChain runs pre/post hooks in order.
type HookChain struct {
	preHooks  []PreHookExecutor
	postHooks []PostHookExecutor
}

// NewHookChain creates a HookChain from slices of hooks.
func NewHookChain(preHooks []PreHookExecutor, postHooks []PostHookExecutor) *HookChain {
	return &HookChain{
		preHooks:  preHooks,
		postHooks: postHooks,
	}
}

// RunPreHooks runs all pre-hooks in order.
// Returns nil to signal the item should be skipped.
func (c *HookChain) RunPreHooks(req *httpmsg.HttpRequestResponse) (*httpmsg.HttpRequestResponse, error) {
	if c == nil || len(c.preHooks) == 0 {
		return req, nil
	}

	current := req
	for _, hook := range c.preHooks {
		result, err := hook.Execute(current)
		if err != nil {
			zap.L().Warn("Pre-hook error, skipping hook",
				zap.String("hook", hook.ID()),
				zap.Error(err))
			continue
		}
		if result == nil {
			return nil, nil // Skip item
		}
		current = result
	}

	return current, nil
}

// RunPostHooks runs all post-hooks in order.
// Returns nil to signal the result should be dropped.
func (c *HookChain) RunPostHooks(result *output.ResultEvent) (*output.ResultEvent, error) {
	if c == nil || len(c.postHooks) == 0 {
		return result, nil
	}

	current := result
	for _, hook := range c.postHooks {
		ret, err := hook.Execute(current)
		if err != nil {
			zap.L().Warn("Post-hook error, skipping hook",
				zap.String("hook", hook.ID()),
				zap.Error(err))
			continue
		}
		if ret == nil {
			return nil, nil // Drop result
		}
		current = ret
	}

	return current, nil
}
