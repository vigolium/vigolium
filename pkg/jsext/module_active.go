package jsext

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/grafana/sobek"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/vigolium/vigolium/pkg/yamlext"
)

// jsCallTimeout hard-bounds a single JS extension callable. Sobek runs JS
// synchronously with no built-in cancellation, so an extension containing an
// infinite loop would otherwise pin a worker goroutine and a CPU core forever —
// even after the executor's per-module watchdog abandons the goroutine. The
// watchdog below interrupts the VM at this deadline.
const defaultJSCallTimeout = 60 * time.Second

// jsCallTimeoutNanos is the bound in force; NewEngine sets it from
// extensions.limits.timeout (SAFE-14).
var jsCallTimeoutNanos atomic.Int64

// SetCallTimeout sets the per-call JS timeout; d <= 0 restores the default.
func SetCallTimeout(d time.Duration) {
	if d <= 0 {
		d = defaultJSCallTimeout
	}
	jsCallTimeoutNanos.Store(int64(d))
}

// jsCallTimeout is the per-call bound in force.
func jsCallTimeout() time.Duration {
	if n := jsCallTimeoutNanos.Load(); n > 0 {
		return time.Duration(n)
	}
	return defaultJSCallTimeout
}

// callJSWithTimeout invokes a JS extension callable under jsCallTimeout. A timer
// goroutine calls vm.Interrupt (safe to call from another goroutine) when the
// deadline elapses, unblocking a runaway loop. The returned poisoned bool is
// true whenever the VM was interrupted: an interrupted runtime carries a sticky
// interrupt flag, so the caller MUST discard it instead of returning it to the
// pool (the pool then builds a fresh VM on the next Get).
func callJSWithTimeout(vm *sobek.Runtime, callable sobek.Callable, this sobek.Value, args ...sobek.Value) (val sobek.Value, err error, poisoned bool) {
	var interrupted atomic.Bool
	limit := jsCallTimeout()
	timer := time.AfterFunc(limit, func() {
		interrupted.Store(true)
		vm.Interrupt("vigolium: JS extension exceeded execution timeout")
	})
	val, err = callable(this, args...)
	timer.Stop()
	if interrupted.Load() {
		if err != nil {
			return nil, fmt.Errorf("JS extension exceeded %s execution timeout: %w", limit, err), true
		}
		// Completed right at the deadline: the result is usable, but the VM was
		// still interrupted, so discard it.
		return val, nil, true
	}
	return val, err, false
}

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
		yamlext.ParseConfidence(script.Metadata.Confidence, severity.Firm),
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
	poisoned := false
	defer func() { m.pool.PutUnlessPoisoned(vm, poisoned) }()

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

	result, err, timedOut := callJSWithTimeout(vm, callable, exports, ctxObj, ipObj)
	poisoned = timedOut
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
	poisoned := false
	defer func() { m.pool.PutUnlessPoisoned(vm, poisoned) }()

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

	result, err, timedOut := callJSWithTimeout(vm, callable, exports, ctxObj)
	poisoned = timedOut
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
	poisoned := false
	defer func() { m.pool.PutUnlessPoisoned(vm, poisoned) }()

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

	result, err, timedOut := callJSWithTimeout(vm, callable, exports, ctxObj)
	poisoned = timedOut
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
		// Single-record annotation: a non-nil error means this record's UPDATE
		// failed, so false is the correct signal (the repository layer logs the
		// cause). A missing record is skipped without error and still reports true.
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

		// hostname = bare hostname (matches browser location.hostname);
		// host = hostname[:port] (matches browser location.host, always includes port).
		if svc := ctx.Request().Service(); svc != nil {
			_ = reqObj.Set("hostname", svc.Host())
			_ = reqObj.Set("host", svc.Host()+":"+strconv.Itoa(svc.Port()))
			_ = reqObj.Set("port", svc.Port())
			_ = reqObj.Set("scheme", svc.Protocol())
		}

		_ = reqObj.Set("headers", newHeadersObject(vm, ctx.Request().Headers()))
	}
	_ = obj.Set("request", reqObj)

	// Response info
	respObj := vm.NewObject()
	if ctx.Response() != nil {
		_ = respObj.Set("status", ctx.Response().StatusCode())
		_ = respObj.Set("body", ctx.Response().BodyToString())
		_ = respObj.Set("raw", string(ctx.Response().Raw()))

		_ = respObj.Set("headers", newHeadersObject(vm, ctx.Response().Headers()))
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
	// Per-result overrides. Anything left unset is filled from the module
	// defaults (confidence, tags) by the executor.
	if v := obj.Get("confidence"); isSet(v) {
		result.Info.Confidence = yamlext.ParseConfidence(v.String(), severity.ConfidenceUndefined)
	}
	if v := obj.Get("tags"); isSet(v) {
		for _, tag := range jsStringSlice(vm, v) {
			result.Info.Tags = append(result.Info.Tags, strings.ToLower(tag))
		}
	}
	if v := obj.Get("cwe"); isSet(v) {
		if cwe := v.String(); cwe != "" {
			result.Metadata = map[string]interface{}{"cwe": cwe}
		}
	}
	if v := obj.Get("fuzzingParameter"); isSet(v) {
		result.FuzzingParameter = v.String()
	} else if v := obj.Get("param"); isSet(v) {
		result.FuzzingParameter = v.String()
	}
	if v := obj.Get("evidence"); isSet(v) {
		result.AdditionalEvidence = jsEvidence(vm, v)
	}

	// Fill defaults from context
	if result.URL == "" && ctx != nil {
		result.URL = ctx.Target()
	}
	if result.Matched == "" {
		result.Matched = result.URL
	}

	return []*output.ResultEvent{result}
}

// isSet reports whether a JS property value is present (not undefined/null).
func isSet(v sobek.Value) bool {
	return v != nil && !sobek.IsUndefined(v) && !sobek.IsNull(v)
}

// jsStringSlice reads a JS string or array of strings into a Go slice.
func jsStringSlice(vm *sobek.Runtime, v sobek.Value) []string {
	if s, ok := v.Export().(string); ok {
		if s == "" {
			return nil
		}
		return []string{s}
	}
	obj := v.ToObject(vm)
	length := obj.Get("length")
	if length == nil || sobek.IsUndefined(length) {
		return nil
	}
	n := int(length.ToInteger())
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		if item := obj.Get(strconv.Itoa(i)); isSet(item) {
			out = append(out, item.String())
		}
	}
	return out
}

// jsEvidence reads a result's `evidence` field: a string, or an array whose
// items are strings or objects ({request, response, note}). Objects are kept
// as compact JSON so nothing the script attached is lost.
func jsEvidence(vm *sobek.Runtime, v sobek.Value) []string {
	toString := func(item sobek.Value) string {
		if s, ok := item.Export().(string); ok {
			return s
		}
		if b, err := json.Marshal(item.Export()); err == nil {
			return string(b)
		}
		return item.String()
	}
	if _, ok := v.Export().(string); ok {
		return []string{v.String()}
	}
	obj := v.ToObject(vm)
	length := obj.Get("length")
	if length == nil || sobek.IsUndefined(length) {
		return []string{toString(v)}
	}
	n := int(length.ToInteger())
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		if item := obj.Get(strconv.Itoa(i)); isSet(item) {
			out = append(out, toString(item))
		}
	}
	return out
}
