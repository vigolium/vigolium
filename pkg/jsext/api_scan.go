package jsext

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/grafana/sobek"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/output"
	"go.uber.org/zap"
)

const extensionScanSource = "extension-scan"

// setupScanAPI registers vigolium.scan.* functions on the VM.
func setupScanAPI(vm *sobek.Runtime, opts APIOptions) {
	scanObj := vm.NewObject()

	// listModules() -> [{id, name, type, severity, description}]
	_ = scanObj.Set("listModules", func(call sobek.FunctionCall) sobek.Value {
		var results []interface{}

		for _, m := range modules.GetActiveModules() {
			entry := map[string]interface{}{
				"id":          m.ID(),
				"name":        m.Name(),
				"type":        "active",
				"severity":    m.Severity().String(),
				"description": m.ShortDescription(),
			}
			results = append(results, entry)
		}
		for _, m := range modules.GetPassiveModules() {
			entry := map[string]interface{}{
				"id":          m.ID(),
				"name":        m.Name(),
				"type":        "passive",
				"severity":    m.Severity().String(),
				"description": m.ShortDescription(),
			}
			results = append(results, entry)
		}

		return vm.ToValue(results)
	})

	// isInScope(host, path) -> bool
	_ = scanObj.Set("isInScope", func(call sobek.FunctionCall) sobek.Value {
		if opts.ScopeMatcher == nil {
			return vm.ToValue(true)
		}
		host := call.Argument(0).String()
		path := call.Argument(1).String()
		return vm.ToValue(opts.ScopeMatcher.InScopeRequest(host, path, "", ""))
	})

	// getScope() -> {host:{include,exclude}, path:{...}, ...}
	_ = scanObj.Set("getScope", func(call sobek.FunctionCall) sobek.Value {
		if opts.ScopeConfig == nil {
			return vm.NewObject()
		}
		return scopeConfigToJS(vm, opts.ScopeConfig)
	})

	// setScope(scopeObj) -> bool
	// Mutates only this VM's copy of the scope matcher.
	_ = scanObj.Set("setScope", func(call sobek.FunctionCall) sobek.Value {
		arg := call.Argument(0)
		if sobek.IsUndefined(arg) || sobek.IsNull(arg) {
			return vm.ToValue(false)
		}

		scopeCfg := jsToScopeConfig(vm, arg.ToObject(vm))
		newMatcher := config.NewScopeMatcher(scopeCfg)
		opts.ScopeMatcher = newMatcher
		return vm.ToValue(true)
	})

	// createFinding({url, matched, name, description, severity, request, response}) -> bool
	_ = scanObj.Set("createFinding", func(call sobek.FunctionCall) sobek.Value {
		arg := call.Argument(0)
		if sobek.IsUndefined(arg) || sobek.IsNull(arg) {
			return vm.ToValue(false)
		}

		obj := arg.ToObject(vm)
		result := &output.ResultEvent{
			Type: "http",
		}

		if v := obj.Get("url"); v != nil && !sobek.IsUndefined(v) {
			result.URL = v.String()
		}
		if v := obj.Get("matched"); v != nil && !sobek.IsUndefined(v) {
			result.Matched = v.String()
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
		if v := obj.Get("request"); v != nil && !sobek.IsUndefined(v) {
			result.Request = v.String()
		}
		if v := obj.Get("response"); v != nil && !sobek.IsUndefined(v) {
			result.Response = v.String()
		}
		if v := obj.Get("additional_evidence"); v != nil && !sobek.IsUndefined(v) {
			if exported := v.Export(); exported != nil {
				if arr, ok := exported.([]interface{}); ok {
					for _, item := range arr {
						if s, ok := item.(string); ok {
							result.AdditionalEvidence = append(result.AdditionalEvidence, s)
						}
					}
				}
			}
		}

		if result.Matched == "" {
			result.Matched = result.URL
		}

		if opts.FindingEmitter != nil {
			opts.FindingEmitter(result)
			return vm.ToValue(true)
		}

		zap.L().Warn("createFinding called but no finding emitter available",
			zap.String("ext", opts.ScriptID))
		return vm.ToValue(false)
	})

	// getCurrentScan() -> {uuid}
	_ = scanObj.Set("getCurrentScan", func(call sobek.FunctionCall) sobek.Value {
		obj := vm.NewObject()
		_ = obj.Set("uuid", opts.ScanUUID)
		return obj
	})

	// startNewScan({targets, modules?, name?}) -> {scan_uuid, queued, errors}
	_ = scanObj.Set("startNewScan", func(call sobek.FunctionCall) sobek.Value {
		repo := opts.Repository
		if repo == nil {
			return startNewScanResultToJS(vm, "", 0, []string{"database not available"})
		}

		arg := call.Argument(0)
		if sobek.IsUndefined(arg) || sobek.IsNull(arg) {
			return startNewScanResultToJS(vm, "", 0, []string{"argument is required"})
		}

		obj := arg.ToObject(vm)

		// Parse targets (required)
		targets := jsStringArray(vm, obj.Get("targets"))
		if len(targets) == 0 {
			return startNewScanResultToJS(vm, "", 0, []string{"targets is required and must be non-empty"})
		}

		// Parse modules (optional, defaults to ["all"])
		modulesList := jsStringArray(vm, obj.Get("modules"))
		if len(modulesList) == 0 {
			modulesList = []string{"all"}
		}

		// Parse name (optional, defaults to "extension-scan")
		scanName := "extension-scan"
		if v := obj.Get("name"); v != nil && !sobek.IsUndefined(v) && !sobek.IsNull(v) {
			if n := strings.TrimSpace(v.String()); n != "" {
				scanName = n
			}
		}

		ctx := context.Background()
		var queued int
		var errors []string

		for _, target := range targets {
			target = strings.TrimSpace(target)
			if target == "" {
				continue
			}

			rr, err := httpmsg.GetRawRequestFromURL(target)
			if err != nil {
				errors = append(errors, fmt.Sprintf("%s: %s", target, err))
				continue
			}

			rr = fetchResponseForIngest(rr, opts.HTTPClient)

			if !isExtIngestInScope(opts.ScopeMatcher, rr) {
				errors = append(errors, fmt.Sprintf("%s: out of scope", target))
				continue
			}

			if _, err := repo.SaveRecord(ctx, rr, extensionScanSource, opts.ProjectUUID); err != nil {
				errors = append(errors, fmt.Sprintf("%s: %s", target, err))
				continue
			}
			queued++
		}

		scanUUID := ""
		if queued > 0 {
			scanUUID = uuid.New().String()
			scan := &database.Scan{
				UUID:        scanUUID,
				ProjectUUID: opts.ProjectUUID,
				Name:        scanName,
				Status:      "pending",
				Target:      strings.Join(targets, ", "),
				Modules:     strings.Join(modulesList, ","),
				ScanSource:  extensionScanSource,
				ScanMode:    "full",
				StartedAt:   time.Now(),
			}
			if err := repo.CreateScanWithCursor(ctx, scan); err != nil {
				errors = append(errors, fmt.Sprintf("failed to create scan record: %s", err))
			}
		}

		return startNewScanResultToJS(vm, scanUUID, queued, errors)
	})

	vigolium := vm.Get("vigolium").ToObject(vm)
	_ = vigolium.Set("scan", scanObj)
}

// scopeConfigToJS converts a ScopeConfig to a JS object.
func scopeConfigToJS(vm *sobek.Runtime, cfg *config.ScopeConfig) sobek.Value {
	obj := vm.NewObject()

	setRule := func(name string, rule config.ScopeRule) {
		ruleObj := vm.NewObject()
		_ = ruleObj.Set("include", rule.Include)
		_ = ruleObj.Set("exclude", rule.Exclude)
		_ = obj.Set(name, ruleObj)
	}

	setRule("host", cfg.Host)
	setRule("path", cfg.Path)
	setRule("status_code", cfg.StatusCode)
	setRule("request_content_type", cfg.RequestContentType)
	setRule("response_content_type", cfg.ResponseContentType)
	setRule("request_string", cfg.RequestString)
	setRule("response_string", cfg.ResponseString)

	return obj
}

// jsToScopeConfig converts a JS object to a ScopeConfig.
func jsToScopeConfig(vm *sobek.Runtime, obj *sobek.Object) config.ScopeConfig {
	cfg := config.ScopeConfig{}

	readRule := func(name string) config.ScopeRule {
		v := obj.Get(name)
		if v == nil || sobek.IsUndefined(v) || sobek.IsNull(v) {
			return config.ScopeRule{}
		}
		ruleObj := v.ToObject(vm)
		return config.ScopeRule{
			Include: jsStringArray(vm, ruleObj.Get("include")),
			Exclude: jsStringArray(vm, ruleObj.Get("exclude")),
		}
	}

	cfg.Host = readRule("host")
	cfg.Path = readRule("path")
	cfg.StatusCode = readRule("status_code")
	cfg.RequestContentType = readRule("request_content_type")
	cfg.ResponseContentType = readRule("response_content_type")
	cfg.RequestString = readRule("request_string")
	cfg.ResponseString = readRule("response_string")

	return cfg
}

// startNewScanResultToJS creates a JS result object for startNewScan.
func startNewScanResultToJS(vm *sobek.Runtime, scanUUID string, queued int, errors []string) sobek.Value {
	obj := vm.NewObject()
	_ = obj.Set("scan_uuid", scanUUID)
	_ = obj.Set("queued", queued)
	if errors == nil {
		errors = []string{}
	}
	_ = obj.Set("errors", errors)
	return obj
}

// jsStringArray extracts a Go string slice from a JS array value.
func jsStringArray(vm *sobek.Runtime, val sobek.Value) []string {
	if val == nil || sobek.IsUndefined(val) || sobek.IsNull(val) {
		return nil
	}
	arr := val.ToObject(vm)
	lengthVal := arr.Get("length")
	if lengthVal == nil || sobek.IsUndefined(lengthVal) {
		return nil
	}
	n := int(lengthVal.ToInteger())
	result := make([]string, 0, n)
	for i := range n {
		item := arr.Get(fmt.Sprintf("%d", i))
		if item != nil && !sobek.IsUndefined(item) {
			result = append(result, item.String())
		}
	}
	return result
}
