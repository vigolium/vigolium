package jsext

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/grafana/sobek"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// JSActiveModule wraps a JS active extension as an ActiveModule.
// No mutex needed — sync.Pool is thread-safe and each VM is an independent runtime.
type JSActiveModule struct {
	modkit.BaseActiveModule
	script *LoadedScript
	pool   *VMPool
}

// NewJSActiveModule creates an ActiveModule from a JS script.
func NewJSActiveModule(script *LoadedScript, opts APIOptions) (*JSActiveModule, error) {
	scanTypes := ParseScanScopes(script.Metadata.ScanTypes)
	sev := ParseSeverity(script.Metadata.Severity)

	pool, err := NewVMPool(script, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to compile JS script %s: %w", script.Path, err)
	}

	base := modkit.NewBaseActiveModule(
		"ext-"+script.Metadata.ID,
		script.Metadata.Name,
		script.Metadata.Description,
		"JS extension: "+script.Metadata.Name,
		script.Metadata.ConfirmationCriteria,
		sev,
		severity.Firm,
		scanTypes,
		modkit.AllInsertionPointTypes,
	)
	base.ModuleTags = script.Metadata.Tags

	return &JSActiveModule{
		BaseActiveModule: base,
		script:           script,
		pool:             pool,
	}, nil
}

func (m *JSActiveModule) ScanPerInsertionPoint(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	_ *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	vm := m.pool.Get()
	defer m.pool.Put(vm)

	// Build context object for JS
	ctxObj := buildRequestContext(vm, ctx)
	enrichRecordContext(vm, ctxObj, ctx, scanCtx, m.pool.opts.Repository)
	ipObj := buildInsertionPointObject(vm, ip)

	// Call scanPerInsertionPoint(ctx, insertion)
	exports := vm.Get("module").ToObject(vm).Get("exports").ToObject(vm)
	fn := exports.Get("scanPerInsertionPoint")
	if fn == nil || sobek.IsUndefined(fn) {
		return nil, nil
	}

	callable, ok := sobek.AssertFunction(fn)
	if !ok {
		return nil, fmt.Errorf("scanPerInsertionPoint is not a function in %s", m.script.Path)
	}

	result, err := callable(exports, ctxObj, ipObj)
	if err != nil {
		return nil, fmt.Errorf("JS error in %s: %w", m.script.Path, err)
	}

	return parseJSResults(vm, result, ctx), nil
}

func (m *JSActiveModule) ScanPerRequest(
	ctx *httpmsg.HttpRequestResponse,
	_ *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	vm := m.pool.Get()
	defer m.pool.Put(vm)

	ctxObj := buildRequestContext(vm, ctx)
	enrichRecordContext(vm, ctxObj, ctx, scanCtx, m.pool.opts.Repository)

	exports := vm.Get("module").ToObject(vm).Get("exports").ToObject(vm)
	fn := exports.Get("scanPerRequest")
	if fn == nil || sobek.IsUndefined(fn) {
		return nil, nil
	}

	callable, ok := sobek.AssertFunction(fn)
	if !ok {
		return nil, fmt.Errorf("scanPerRequest is not a function in %s", m.script.Path)
	}

	result, err := callable(exports, ctxObj)
	if err != nil {
		return nil, fmt.Errorf("JS error in %s: %w", m.script.Path, err)
	}

	return parseJSResults(vm, result, ctx), nil
}

func (m *JSActiveModule) ScanPerHost(
	ctx *httpmsg.HttpRequestResponse,
	_ *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	vm := m.pool.Get()
	defer m.pool.Put(vm)

	ctxObj := buildRequestContext(vm, ctx)
	enrichRecordContext(vm, ctxObj, ctx, scanCtx, m.pool.opts.Repository)

	exports := vm.Get("module").ToObject(vm).Get("exports").ToObject(vm)
	fn := exports.Get("scanPerHost")
	if fn == nil || sobek.IsUndefined(fn) {
		return nil, nil
	}

	callable, ok := sobek.AssertFunction(fn)
	if !ok {
		return nil, fmt.Errorf("scanPerHost is not a function in %s", m.script.Path)
	}

	result, err := callable(exports, ctxObj)
	if err != nil {
		return nil, fmt.Errorf("JS error in %s: %w", m.script.Path, err)
	}

	return parseJSResults(vm, result, ctx), nil
}

// enrichRecordContext adds ctx.record and vigolium.record with uuid, annotate(),
// addRiskScore(), and addRemarks() for the current HTTP record.
func enrichRecordContext(vm *sobek.Runtime, ctxObj sobek.Value, ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext, repo *database.Repository) {
	recordObj := buildRecordObject(vm, ctx, scanCtx, repo)

	// Set on ctx.record
	_ = ctxObj.ToObject(vm).Set("record", recordObj)

	// Set on vigolium.record (alias)
	vigolium := vm.Get("vigolium").ToObject(vm)
	_ = vigolium.Set("record", recordObj)
}

// buildRecordObject creates the shared record object with uuid, annotate(),
// addRiskScore(), and addRemarks().
func buildRecordObject(vm *sobek.Runtime, ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext, repo *database.Repository) *sobek.Object {
	recordObj := vm.NewObject()

	// Resolve UUID from the executor's request→UUID mapping
	uuid := ""
	if scanCtx != nil && scanCtx.RequestUUIDResolver != nil && ctx != nil {
		uuid = scanCtx.RequestUUIDResolver.ResolveRequestUUID(ctx.ID())
	}
	_ = recordObj.Set("uuid", uuid)

	// annotate(patch) — replace risk_score and/or remarks
	_ = recordObj.Set("annotate", func(call sobek.FunctionCall) sobek.Value {
		if uuid == "" || repo == nil {
			return vm.ToValue(false)
		}
		patchArg := call.Argument(0)
		if sobek.IsUndefined(patchArg) || sobek.IsNull(patchArg) {
			return vm.ToValue(false)
		}
		patchObj := patchArg.ToObject(vm)

		var riskScore *int
		var remarks []string

		if v := patchObj.Get("risk_score"); v != nil && !sobek.IsUndefined(v) && !sobek.IsNull(v) {
			rs := clampRiskScore(int(v.ToInteger()))
			riskScore = &rs
		}
		if v := patchObj.Get("remarks"); v != nil && !sobek.IsUndefined(v) && !sobek.IsNull(v) {
			raw, _ := json.Marshal(v.Export())
			var strs []string
			if jsonErr := json.Unmarshal(raw, &strs); jsonErr == nil {
				remarks = strs
			}
		}

		if err := repo.UpdateRecordAnnotations(context.Background(), uuid, riskScore, remarks); err != nil {
			return vm.ToValue(false)
		}
		return vm.ToValue(true)
	})

	// addRiskScore(delta) — increment risk_score by delta (read-modify-write)
	_ = recordObj.Set("addRiskScore", func(call sobek.FunctionCall) sobek.Value {
		if uuid == "" || repo == nil {
			return vm.ToValue(false)
		}
		delta := int(call.Argument(0).ToInteger())
		if delta == 0 {
			return vm.ToValue(true)
		}

		record, err := repo.GetRecordByUUID(context.Background(), uuid)
		if err != nil {
			return vm.ToValue(false)
		}
		newScore := clampRiskScore(record.RiskScore + delta)
		if err := repo.UpdateRecordAnnotations(context.Background(), uuid, &newScore, nil); err != nil {
			return vm.ToValue(false)
		}
		return vm.ToValue(true)
	})

	// addRemarks(remarks) — append remarks with deduplication
	_ = recordObj.Set("addRemarks", func(call sobek.FunctionCall) sobek.Value {
		if uuid == "" || repo == nil {
			return vm.ToValue(false)
		}
		remarksArg := call.Argument(0)
		if sobek.IsUndefined(remarksArg) || sobek.IsNull(remarksArg) {
			return vm.ToValue(false)
		}
		raw, _ := json.Marshal(remarksArg.Export())
		var strs []string
		if err := json.Unmarshal(raw, &strs); err != nil || len(strs) == 0 {
			return vm.ToValue(false)
		}
		// Deduplicate input remarks before sending to DB
		seen := make(map[string]struct{}, len(strs))
		deduped := make([]string, 0, len(strs))
		for _, s := range strs {
			if _, ok := seen[s]; !ok {
				seen[s] = struct{}{}
				deduped = append(deduped, s)
			}
		}
		annotations := map[string][]string{uuid: deduped}
		if err := repo.AppendRemarks(context.Background(), annotations); err != nil {
			return vm.ToValue(false)
		}
		return vm.ToValue(true)
	})

	return recordObj
}

// clampRiskScore clamps a risk score to [0, 100].
func clampRiskScore(score int) int {
	if score < 0 {
		return 0
	}
	if score > 100 {
		return 100
	}
	return score
}

func buildRequestContext(vm *sobek.Runtime, ctx *httpmsg.HttpRequestResponse) sobek.Value {
	obj := vm.NewObject()

	// Request info
	reqObj := vm.NewObject()
	if ctx.Request() != nil {
		_ = reqObj.Set("raw", string(ctx.Request().Raw()))
		_ = reqObj.Set("method", ctx.Request().Method())
		_ = reqObj.Set("url", ctx.Target())

		headersObj := vm.NewObject()
		for _, h := range ctx.Request().Headers() {
			_ = headersObj.Set(h.Name, h.Value)
		}
		_ = reqObj.Set("headers", headersObj)
	}
	_ = obj.Set("request", reqObj)

	// Response info
	respObj := vm.NewObject()
	if ctx.Response() != nil {
		_ = respObj.Set("status", ctx.Response().StatusCode())
		_ = respObj.Set("body", ctx.Response().BodyToString())
		_ = respObj.Set("raw", string(ctx.Response().Raw()))

		headersObj := vm.NewObject()
		for _, h := range ctx.Response().Headers() {
			_ = headersObj.Set(h.Name, h.Value)
		}
		_ = respObj.Set("headers", headersObj)
	}
	_ = obj.Set("response", respObj)

	return obj
}

func buildInsertionPointObject(vm *sobek.Runtime, ip httpmsg.InsertionPoint) sobek.Value {
	obj := vm.NewObject()
	_ = obj.Set("name", ip.Name())
	_ = obj.Set("baseValue", ip.BaseValue())
	_ = obj.Set("type", ip.Type().String())

	_ = obj.Set("buildRequest", func(call sobek.FunctionCall) sobek.Value {
		payload := call.Argument(0).String()
		built := ip.BuildRequest([]byte(payload))
		return vm.ToValue(string(built))
	})

	return obj
}

// parseJSResults converts JS return value (array of result objects) to ResultEvents.
func parseJSResults(vm *sobek.Runtime, val sobek.Value, ctx *httpmsg.HttpRequestResponse) []*output.ResultEvent {
	if val == nil || sobek.IsUndefined(val) || sobek.IsNull(val) {
		return nil
	}

	arr := val.ToObject(vm)
	lengthVal := arr.Get("length")
	if lengthVal == nil || sobek.IsUndefined(lengthVal) {
		// Might be a single object, not an array
		return parseSingleJSResult(vm, arr, ctx)
	}

	n := int(lengthVal.ToInteger())
	if n == 0 {
		return nil
	}

	var results []*output.ResultEvent
	for i := range n {
		item := arr.Get(fmt.Sprintf("%d", i))
		if item == nil || sobek.IsUndefined(item) {
			continue
		}
		results = append(results, parseSingleJSResult(vm, item.ToObject(vm), ctx)...)
	}

	return results
}

func parseSingleJSResult(vm *sobek.Runtime, obj *sobek.Object, ctx *httpmsg.HttpRequestResponse) []*output.ResultEvent {
	result := &output.ResultEvent{
		Type: "http",
	}

	if v := obj.Get("matched"); v != nil && !sobek.IsUndefined(v) {
		result.Matched = v.String()
	}
	if v := obj.Get("url"); v != nil && !sobek.IsUndefined(v) {
		result.URL = v.String()
	}
	if v := obj.Get("request"); v != nil && !sobek.IsUndefined(v) {
		result.Request = v.String()
	}
	if v := obj.Get("response"); v != nil && !sobek.IsUndefined(v) {
		result.Response = v.String()
	}
	if v := obj.Get("name"); v != nil && !sobek.IsUndefined(v) {
		result.Info.Name = v.String()
	}
	if v := obj.Get("description"); v != nil && !sobek.IsUndefined(v) {
		result.Info.Description = v.String()
	}
	if v := obj.Get("severity"); v != nil && !sobek.IsUndefined(v) {
		result.Info.Severity = ParseSeverity(v.String())
	}

	// Fill defaults from context
	if result.URL == "" && ctx != nil {
		result.URL = ctx.Target()
	}
	if result.Matched == "" {
		result.Matched = result.URL
	}

	_ = vm // suppress unused warning in future
	return []*output.ResultEvent{result}
}
