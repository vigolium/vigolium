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

// scanFuncDefs returns the JSFuncDef entries for vigolium.scan.*.
func scanFuncDefs() []JSFuncDef {
	return []JSFuncDef{
		{
			Namespace: NsScan, Name: "listModules",
			Category: CatScan, Signature: ".listModules()", Returns: "[{id, name, type, severity, description}]",
			Description: "List all registered scanner modules (active + passive).", Example: exScanListModules,
			MakeHandler: func(vm *sobek.Runtime, opts APIOptions) func(sobek.FunctionCall) sobek.Value {
				return func(call sobek.FunctionCall) sobek.Value {
					var results []interface{}

					for _, m := range modules.GetActiveModules() {
						tags := m.Tags()
						if tags == nil {
							tags = []string{}
						}
						entry := map[string]interface{}{
							"id":          m.ID(),
							"name":        m.Name(),
							"type":        "active",
							"severity":    m.Severity().String(),
							"description": m.ShortDescription(),
							"tags":        tags,
						}
						results = append(results, entry)
					}
					for _, m := range modules.GetPassiveModules() {
						tags := m.Tags()
						if tags == nil {
							tags = []string{}
						}
						entry := map[string]interface{}{
							"id":          m.ID(),
							"name":        m.Name(),
							"type":        "passive",
							"severity":    m.Severity().String(),
							"description": m.ShortDescription(),
							"tags":        tags,
						}
						results = append(results, entry)
					}

					return vm.ToValue(results)
				}
			},
		},
		{
			Namespace: NsScan, Name: "listModuleTags",
			Category: CatScan, Signature: ".listModuleTags()", Returns: "string[]",
			Description: "Returns all unique tags across all registered modules.", Example: "",
			MakeHandler: func(vm *sobek.Runtime, opts APIOptions) func(sobek.FunctionCall) sobek.Value {
				return func(call sobek.FunctionCall) sobek.Value {
					tagSet := make(map[string]struct{})

					for _, m := range modules.GetActiveModules() {
						for _, t := range m.Tags() {
							tagSet[strings.ToLower(t)] = struct{}{}
						}
					}
					for _, m := range modules.GetPassiveModules() {
						for _, t := range m.Tags() {
							tagSet[strings.ToLower(t)] = struct{}{}
						}
					}

					tags := make([]interface{}, 0, len(tagSet))
					for t := range tagSet {
						tags = append(tags, t)
					}
					return vm.ToValue(tags)
				}
			},
		},
		{
			Namespace: NsScan, Name: "listModulesByTag",
			Category: CatScan, Signature: ".listModulesByTag(tag: string)", Returns: "[{id, name, type, severity, description, tags}]",
			Description: "Returns all modules that have the given tag (case-insensitive).", Example: "",
			MakeHandler: func(vm *sobek.Runtime, opts APIOptions) func(sobek.FunctionCall) sobek.Value {
				return func(call sobek.FunctionCall) sobek.Value {
					tag := strings.ToLower(call.Argument(0).String())
					if tag == "" {
						return vm.NewArray()
					}

					var results []interface{}

					hasTag := func(moduleTags []string) bool {
						for _, t := range moduleTags {
							if strings.ToLower(t) == tag {
								return true
							}
						}
						return false
					}

					for _, m := range modules.GetActiveModules() {
						if hasTag(m.Tags()) {
							tags := m.Tags()
							if tags == nil {
								tags = []string{}
							}
							results = append(results, map[string]interface{}{
								"id":          m.ID(),
								"name":        m.Name(),
								"type":        "active",
								"severity":    m.Severity().String(),
								"description": m.ShortDescription(),
								"tags":        tags,
							})
						}
					}
					for _, m := range modules.GetPassiveModules() {
						if hasTag(m.Tags()) {
							tags := m.Tags()
							if tags == nil {
								tags = []string{}
							}
							results = append(results, map[string]interface{}{
								"id":          m.ID(),
								"name":        m.Name(),
								"type":        "passive",
								"severity":    m.Severity().String(),
								"description": m.ShortDescription(),
								"tags":        tags,
							})
						}
					}

					if results == nil {
						return vm.NewArray()
					}
					return vm.ToValue(results)
				}
			},
		},
		{
			Namespace: NsScan, Name: "isInScope",
			Category: CatScan, Signature: ".isInScope(host: string, path: string)", Returns: "bool",
			Description: "Check if a host+path combination is within the current scan scope.", Example: exScanIsInScope,
			MakeHandler: func(vm *sobek.Runtime, opts APIOptions) func(sobek.FunctionCall) sobek.Value {
				return func(call sobek.FunctionCall) sobek.Value {
					if opts.ScopeMatcher == nil {
						return vm.ToValue(true)
					}
					host := call.Argument(0).String()
					path := call.Argument(1).String()
					return vm.ToValue(opts.ScopeMatcher.InScopeRequest(host, path, "", ""))
				}
			},
		},
		{
			Namespace: NsScan, Name: "getScope",
			Category: CatScan, Signature: ".getScope()", Returns: "{host, path, status_code, ...}",
			Description: "Get the current scope configuration. Each key has {include, exclude} arrays.", Example: exScanGetScope,
			MakeHandler: func(vm *sobek.Runtime, opts APIOptions) func(sobek.FunctionCall) sobek.Value {
				return func(call sobek.FunctionCall) sobek.Value {
					if opts.ScopeConfig == nil {
						return vm.NewObject()
					}
					return scopeConfigToJS(vm, opts.ScopeConfig)
				}
			},
		},
		{
			Namespace: NsScan, Name: "setScope",
			Category: CatScan, Signature: ".setScope(scopeObj: object)", Returns: "bool",
			Description: "Update the scope configuration for this VM instance.", Example: exScanSetScope,
			MakeHandler: func(vm *sobek.Runtime, opts APIOptions) func(sobek.FunctionCall) sobek.Value {
				return func(call sobek.FunctionCall) sobek.Value {
					arg := call.Argument(0)
					if sobek.IsUndefined(arg) || sobek.IsNull(arg) {
						return vm.ToValue(false)
					}

					scopeCfg := jsToScopeConfig(vm, arg.ToObject(vm))
					newMatcher := config.NewScopeMatcher(scopeCfg)
					opts.ScopeMatcher = newMatcher
					return vm.ToValue(true)
				}
			},
		},
		{
			Namespace: NsScan, Name: "createFinding",
			Category: CatScan, Signature: ".createFinding({url, matched, name, description, severity, request, response, additional_evidence})", Returns: "bool",
			Description: "Emit a finding from a hook or module. Severity: critical, high, medium, low, info.", Example: exScanCreateFinding,
			MakeHandler: func(vm *sobek.Runtime, opts APIOptions) func(sobek.FunctionCall) sobek.Value {
				return func(call sobek.FunctionCall) sobek.Value {
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
				}
			},
		},
		{
			Namespace: NsScan, Name: "getCurrentScan",
			Category: CatScan, Signature: ".getCurrentScan()", Returns: "{uuid}",
			Description: "Get information about the current scan session.", Example: exScanGetCurrentScan,
			MakeHandler: func(vm *sobek.Runtime, opts APIOptions) func(sobek.FunctionCall) sobek.Value {
				return func(call sobek.FunctionCall) sobek.Value {
					obj := vm.NewObject()
					_ = obj.Set("uuid", opts.ScanUUID)
					return obj
				}
			},
		},
		{
			Namespace: NsScan, Name: "startNewScan",
			Category: CatScan, Signature: ".startNewScan({targets: string[], modules?: string[], name?: string})", Returns: "{scan_uuid, queued, errors}",
			Description: "Queue targets for scanning and create a new scan record. Modules default to [\"all\"], name defaults to \"extension-scan\".", Example: exScanStartNewScan,
			MakeHandler: func(vm *sobek.Runtime, opts APIOptions) func(sobek.FunctionCall) sobek.Value {
				return func(call sobek.FunctionCall) sobek.Value {
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
				}
			},
		},
		{
			Namespace: NsScan, Name: "scanRecords",
			Category: CatScan, Signature: ".scanRecords({uuids: string[], modules?: string[], tags?: string[], name?: string})", Returns: "{scan_uuid, record_count, errors}",
			Description: "Queue a scan for existing database records by their UUIDs.", Example: "",
			MakeHandler: func(vm *sobek.Runtime, opts APIOptions) func(sobek.FunctionCall) sobek.Value {
				return func(call sobek.FunctionCall) sobek.Value {
					repo := opts.Repository
					if repo == nil {
						return scanRecordsResultToJS(vm, "", 0, []string{"database not available"})
					}

					arg := call.Argument(0)
					if sobek.IsUndefined(arg) || sobek.IsNull(arg) {
						return scanRecordsResultToJS(vm, "", 0, []string{"argument is required"})
					}

					obj := arg.ToObject(vm)

					// Parse uuids (required)
					uuids := jsStringArray(vm, obj.Get("uuids"))
					if len(uuids) == 0 {
						return scanRecordsResultToJS(vm, "", 0, []string{"uuids is required and must be non-empty"})
					}

					// Parse modules (optional, defaults to ["all"])
					modulesList := jsStringArray(vm, obj.Get("modules"))

					// Parse tags (optional) — resolve to module IDs
					tagsList := jsStringArray(vm, obj.Get("tags"))
					if len(tagsList) > 0 {
						resolved := modules.ResolveModuleTags(tagsList)
						modulesList = append(modulesList, resolved...)
					}
					if len(modulesList) == 0 {
						modulesList = []string{"all"}
					}

					// Parse name (optional)
					scanName := "extension-scan-records"
					if v := obj.Get("name"); v != nil && !sobek.IsUndefined(v) && !sobek.IsNull(v) {
						if n := strings.TrimSpace(v.String()); n != "" {
							scanName = n
						}
					}

					ctx := context.Background()

					// Fetch and validate records
					records, err := repo.GetRecordsByUUIDs(ctx, uuids)
					if err != nil {
						return scanRecordsResultToJS(vm, "", 0, []string{fmt.Sprintf("failed to fetch records: %s", err)})
					}

					if len(records) == 0 {
						return scanRecordsResultToJS(vm, "", 0, []string{"no matching records found"})
					}

					// Collect targets for the scan record
					var targets []string
					var errors []string
					seen := make(map[string]bool, len(records))
					for _, r := range records {
						seen[r.UUID] = true
						if r.URL != "" {
							targets = append(targets, r.URL)
						} else {
							targets = append(targets, fmt.Sprintf("%s://%s:%d%s", r.Scheme, r.Hostname, r.Port, r.Path))
						}
					}

					// Report missing UUIDs
					for _, u := range uuids {
						if !seen[u] {
							errors = append(errors, fmt.Sprintf("%s: record not found", u))
						}
					}

					// Create scan entry
					scanUUID := uuid.New().String()
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

					return scanRecordsResultToJS(vm, scanUUID, len(records), errors)
				}
			},
		},
	}
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

// scanRecordsResultToJS creates a JS result object for scanRecords.
func scanRecordsResultToJS(vm *sobek.Runtime, scanUUID string, recordCount int, errors []string) sobek.Value {
	obj := vm.NewObject()
	_ = obj.Set("scan_uuid", scanUUID)
	_ = obj.Set("record_count", recordCount)
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
