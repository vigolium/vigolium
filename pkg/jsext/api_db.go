package jsext

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/grafana/sobek"
	"github.com/vigolium/vigolium/pkg/anomaly"
	"github.com/vigolium/vigolium/pkg/database"
	"go.uber.org/zap"
)

// dbFuncDefs returns the JSFuncDef entries for vigolium.db.*.
func dbFuncDefs() []JSFuncDef {
	defs := []JSFuncDef{
		// ── vigolium.db.records ───────────────────────────────────────────────

		{
			Namespace: NsDBRecords, Name: "query",
			Category:    CatDBRecords,
			Signature:   ".query(filters?: {hostname?, path?, methods?, status_codes?, limit?, offset?, sort_by?, sort_asc?})",
			Returns:     "DBRecord[]",
			Description: "Query HTTP records from the database with optional filters.",
			Example:     exDBRecordsQuery,
			MakeHandler: func(vm *sobek.Runtime, opts APIOptions) func(sobek.FunctionCall) sobek.Value {
				repo := opts.Repository
				return func(call sobek.FunctionCall) sobek.Value {
					filters := jsToQueryFilters(vm, call.Argument(0))
					qb := database.NewQueryBuilder(repo.DB(), filters)
					records, err := qb.Execute(context.Background())
					if err != nil {
						zap.L().Debug("db.records.query failed", zap.Error(err))
						return vm.NewArray()
					}
					return httpRecordsToJS(vm, records)
				}
			},
		},
		{
			Namespace: NsDBRecords, Name: "get",
			Category:    CatDBRecords,
			Signature:   ".get(uuid: string)",
			Returns:     "DBRecord | null",
			Description: "Get a single HTTP record by UUID.",
			Example:     exDBRecordsGet,
			MakeHandler: func(vm *sobek.Runtime, opts APIOptions) func(sobek.FunctionCall) sobek.Value {
				repo := opts.Repository
				return func(call sobek.FunctionCall) sobek.Value {
					uuid := call.Argument(0).String()
					record, err := repo.GetRecordByUUID(context.Background(), uuid)
					if err != nil {
						return sobek.Null()
					}
					return vm.ToValue(httpRecordToMap(record))
				}
			},
		},
		{
			Namespace: NsDBRecords, Name: "getRelated",
			Category:    CatDBRecords,
			Signature:   ".getRelated(uuid: string, opts?: {limit?: number})",
			Returns:     "DBRecord[]",
			Description: "Get HTTP records related to a given record UUID.",
			Example:     exDBRecordsGetRelated,
			MakeHandler: func(vm *sobek.Runtime, opts APIOptions) func(sobek.FunctionCall) sobek.Value {
				repo := opts.Repository
				return func(call sobek.FunctionCall) sobek.Value {
					uuid := call.Argument(0).String()
					limit := 10
					optsArg := call.Argument(1)
					if !sobek.IsUndefined(optsArg) && !sobek.IsNull(optsArg) {
						obj := optsArg.ToObject(vm)
						if v := obj.Get("limit"); v != nil && !sobek.IsUndefined(v) {
							limit = int(v.ToInteger())
						}
					}
					records, err := repo.GetRelatedRecords(context.Background(), uuid, limit)
					if err != nil {
						zap.L().Debug("db.records.getRelated failed", zap.Error(err))
						return vm.NewArray()
					}
					return httpRecordsToJS(vm, records)
				}
			},
		},
		{
			Namespace: NsDBRecords, Name: "annotate",
			Category:    CatDBRecords,
			Signature:   ".annotate(uuid: string, patch: {risk_score?, remarks?})",
			Returns:     "bool",
			Description: "Update annotations (risk score, remarks) on an HTTP record.",
			Example:     exDBRecordsAnnotate,
			MakeHandler: func(vm *sobek.Runtime, opts APIOptions) func(sobek.FunctionCall) sobek.Value {
				repo := opts.Repository
				return func(call sobek.FunctionCall) sobek.Value {
					uuid := call.Argument(0).String()
					patchArg := call.Argument(1)
					if sobek.IsUndefined(patchArg) || sobek.IsNull(patchArg) {
						return vm.ToValue(false)
					}
					patchObj := patchArg.ToObject(vm)

					var riskScore *int
					var remarks []string

					if v := patchObj.Get("risk_score"); v != nil && !sobek.IsUndefined(v) && !sobek.IsNull(v) {
						rs := int(v.ToInteger())
						riskScore = &rs
					}
					if v := patchObj.Get("remarks"); v != nil && !sobek.IsUndefined(v) && !sobek.IsNull(v) {
						raw, _ := json.Marshal(v.Export())
						var strs []string
						if err := json.Unmarshal(raw, &strs); err == nil {
							remarks = strs
						}
					}

					if err := repo.UpdateRecordAnnotations(context.Background(), uuid, riskScore, remarks); err != nil {
						zap.L().Debug("db.records.annotate failed", zap.Error(err))
						return vm.ToValue(false)
					}
					return vm.ToValue(true)
				}
			},
		},

		// ── vigolium.db.findings ──────────────────────────────────────────────

		{
			Namespace: NsDBFindings, Name: "query",
			Category:    CatDBFindings,
			Signature:   ".query(filters?: {severity?, module_name?, scan_uuid?, limit?, offset?})",
			Returns:     "DBFinding[]",
			Description: "Query findings from the database with optional filters.",
			Example:     exDBFindingsQuery,
			MakeHandler: func(vm *sobek.Runtime, opts APIOptions) func(sobek.FunctionCall) sobek.Value {
				repo := opts.Repository
				return func(call sobek.FunctionCall) sobek.Value {
					filters := jsToQueryFilters(vm, call.Argument(0))
					fqb := database.NewFindingsQueryBuilder(repo.DB(), filters)
					findings, err := fqb.Execute(context.Background())
					if err != nil {
						zap.L().Debug("db.findings.query failed", zap.Error(err))
						return vm.NewArray()
					}
					return findingsToJS(vm, findings)
				}
			},
		},
		{
			Namespace: NsDBFindings, Name: "get",
			Category:    CatDBFindings,
			Signature:   ".get(id: number)",
			Returns:     "DBFinding | null",
			Description: "Get a single finding by ID.",
			Example:     exDBFindingsGet,
			MakeHandler: func(vm *sobek.Runtime, opts APIOptions) func(sobek.FunctionCall) sobek.Value {
				repo := opts.Repository
				return func(call sobek.FunctionCall) sobek.Value {
					id := call.Argument(0).ToInteger()
					finding, err := repo.GetFindingByID(context.Background(), id)
					if err != nil {
						return sobek.Null()
					}
					return vm.ToValue(findingToMap(finding))
				}
			},
		},
		{
			Namespace: NsDBFindings, Name: "getByRecord",
			Category:    CatDBFindings,
			Signature:   ".getByRecord(uuid: string)",
			Returns:     "DBFinding[]",
			Description: "Get all findings associated with an HTTP record UUID.",
			Example:     exDBFindingsGetByRecord,
			MakeHandler: func(vm *sobek.Runtime, opts APIOptions) func(sobek.FunctionCall) sobek.Value {
				repo := opts.Repository
				return func(call sobek.FunctionCall) sobek.Value {
					uuid := call.Argument(0).String()
					findings, err := repo.GetFindingsByRecordUUID(context.Background(), uuid)
					if err != nil {
						zap.L().Debug("db.findings.getByRecord failed", zap.Error(err))
						return vm.NewArray()
					}
					return findingsToJS(vm, findings)
				}
			},
		},
		{
			Namespace: NsDBFindings, Name: "create",
			Category:    CatDBFindings,
			Signature:   ".create(finding: {module_id, module_name, severity?, confidence?, description?, ...})",
			Returns:     "bool",
			Description: "Create a new finding in the database.",
			Example:     exDBFindingsCreate,
			MakeHandler: func(vm *sobek.Runtime, opts APIOptions) func(sobek.FunctionCall) sobek.Value {
				repo := opts.Repository
				return func(call sobek.FunctionCall) sobek.Value {
					fArg := call.Argument(0)
					if sobek.IsUndefined(fArg) || sobek.IsNull(fArg) {
						return vm.ToValue(false)
					}
					finding := jsToFinding(vm, fArg.ToObject(vm))
					if finding == nil {
						return vm.ToValue(false)
					}
					if err := repo.SaveFindingDirect(context.Background(), finding); err != nil {
						zap.L().Debug("db.findings.create failed", zap.Error(err))
						return vm.ToValue(false)
					}
					return vm.ToValue(true)
				}
			},
		},

		// ── vigolium.db (top-level) ──────────────────────────────────────────

		{
			Namespace: NsDB, Name: "compareResponses",
			Category:    CatDBAnalysis,
			Signature:   ".compareResponses(records: object[])",
			Returns:     "{all_similar, scores, variant_count, summary}",
			Description: "Compare HTTP responses by anomaly score. Each input should have {uuid, status_code, response_body, response_headers}.",
			Example:     exDBCompareResponses,
			MakeHandler: func(vm *sobek.Runtime, _ APIOptions) func(sobek.FunctionCall) sobek.Value {
				return func(call sobek.FunctionCall) sobek.Value {
					return dbCompareResponses(vm, call)
				}
			},
		},
	}

	// Append grouped record functions from api_db_grouped.go.
	defs = append(defs, dbGroupedFuncDefs()...)

	return defs
}

// dbCompareResponses implements vigolium.db.compareResponses.
func dbCompareResponses(vm *sobek.Runtime, call sobek.FunctionCall) sobek.Value {
	if len(call.Arguments) == 0 || sobek.IsUndefined(call.Arguments[0]) || sobek.IsNull(call.Arguments[0]) {
		return dbEmptyCompareResult(vm)
	}

	// JSON round-trip to extract typed fields from the JS array
	exported := call.Arguments[0].Export()
	raw, err := json.Marshal(exported)
	if err != nil {
		return dbEmptyCompareResult(vm)
	}

	var items []struct {
		UUID            string              `json:"uuid"`
		StatusCode      int                 `json:"status_code"`
		ResponseBody    string              `json:"response_body"`
		ResponseHeaders map[string][]string `json:"response_headers"`
	}
	if err := json.Unmarshal(raw, &items); err != nil {
		return dbEmptyCompareResult(vm)
	}
	if len(items) == 0 {
		return dbEmptyCompareResult(vm)
	}

	engine := anomaly.NewDefaultEngine()
	recs := make([]*anomaly.ResponseRecord, 0, len(items))
	for _, item := range items {
		attrs, extractErr := anomaly.ExtractAttributesFromRaw(item.StatusCode, item.ResponseBody, item.ResponseHeaders)
		if extractErr != nil {
			zap.L().Debug("db.compareResponses: ExtractAttributesFromRaw failed", zap.Error(extractErr))
			attrs = anomaly.NewAttributeSet()
		}
		recs = append(recs, &anomaly.ResponseRecord{
			Attributes: *attrs,
			Metadata:   item.UUID,
		})
	}

	if err := engine.RankAndSort(recs); err != nil {
		zap.L().Debug("db.compareResponses: RankAndSort failed", zap.Error(err))
		return dbEmptyCompareResult(vm)
	}

	// Build result
	scores := make([]interface{}, len(recs))
	variantCount := 0
	maxScore := 0
	diffScores := make([]string, 0)

	for i, rec := range recs {
		uuid := ""
		if s, ok := rec.Metadata.(string); ok {
			uuid = s
		}
		scores[i] = map[string]interface{}{
			"uuid":  uuid,
			"score": rec.Score,
		}
		if rec.Score > 0 {
			variantCount++
			diffScores = append(diffScores, fmt.Sprintf("%d", rec.Score))
			if rec.Score > maxScore {
				maxScore = rec.Score
			}
		}
	}

	allSimilar := maxScore == 0
	summary := ""
	if allSimilar {
		summary = fmt.Sprintf("all %d responses are similar", len(recs))
	} else {
		summary = fmt.Sprintf("%d/%d responses differ (scores: %s)",
			variantCount, len(recs), strings.Join(diffScores, ", "))
	}

	result := vm.NewObject()
	_ = result.Set("all_similar", allSimilar)
	_ = result.Set("scores", scores)
	_ = result.Set("variant_count", variantCount)
	_ = result.Set("summary", summary)
	return result
}

func dbEmptyCompareResult(vm *sobek.Runtime) sobek.Value {
	result := vm.NewObject()
	_ = result.Set("all_similar", true)
	_ = result.Set("scores", []interface{}{})
	_ = result.Set("variant_count", 0)
	_ = result.Set("summary", "no records to compare")
	return result
}

// ── conversion helpers ─────────────────────────────────────────────────────────

func httpRecordToMap(r *database.HTTPRecord) map[string]interface{} {
	m := map[string]interface{}{
		"uuid":         r.UUID,
		"scheme":       r.Scheme,
		"hostname":     r.Hostname,
		"port":         r.Port,
		"method":       r.Method,
		"path":         r.Path,
		"url":          r.URL,
		"http_version": r.HTTPVersion,
		"status_code":  r.StatusCode,
		"has_response": r.HasResponse,
		"risk_score":   r.RiskScore,
		"source":       r.Source,
		"sent_at":      r.SentAt.Format(time.RFC3339),
		"response_body": func() string {
			if len(r.ResponseBody) > 0 {
				return string(r.ResponseBody)
			}
			return ""
		}(),
	}
	if r.ResponseContentType != "" {
		m["response_content_type"] = r.ResponseContentType
	}
	if r.RequestContentType != "" {
		m["request_content_type"] = r.RequestContentType
	}
	if r.ResponseTimeMs > 0 {
		m["response_time_ms"] = r.ResponseTimeMs
	}
	if r.StatusPhrase != "" {
		m["status_phrase"] = r.StatusPhrase
	}
	if r.ResponseTitle != "" {
		m["response_title"] = r.ResponseTitle
	}
	if len(r.Remarks) > 0 {
		m["remarks"] = r.Remarks
	}
	if r.ResponseHeaders != nil {
		m["response_headers"] = r.ResponseHeaders
	}
	if r.RequestHeaders != nil {
		m["request_headers"] = r.RequestHeaders
	}
	if len(r.RequestBody) > 0 {
		m["request_body"] = string(r.RequestBody)
	}
	return m
}

func httpRecordsToJS(vm *sobek.Runtime, records []*database.HTTPRecord) sobek.Value {
	arr := make([]interface{}, len(records))
	for i, r := range records {
		arr[i] = httpRecordToMap(r)
	}
	return vm.ToValue(arr)
}

func findingToMap(f *database.Finding) map[string]interface{} {
	m := map[string]interface{}{
		"id":           f.ID,
		"module_id":    f.ModuleID,
		"module_name":  f.ModuleName,
		"severity":     f.Severity,
		"confidence":   f.Confidence,
		"finding_hash": f.FindingHash,
		"found_at":     f.FoundAt.Format(time.RFC3339),
	}
	if f.Description != "" {
		m["description"] = f.Description
	}
	if f.Request != "" {
		m["request"] = f.Request
	}
	if f.Response != "" {
		m["response"] = f.Response
	}
	if len(f.Tags) > 0 {
		m["tags"] = f.Tags
	}
	if len(f.MatchedAt) > 0 {
		m["matched_at"] = f.MatchedAt
	}
	if len(f.ExtractedResults) > 0 {
		m["extracted_results"] = f.ExtractedResults
	}
	if len(f.AdditionalEvidence) > 0 {
		m["additional_evidence"] = f.AdditionalEvidence
	}
	if len(f.HTTPRecordUUIDs) > 0 {
		m["http_record_uuids"] = f.HTTPRecordUUIDs
	}
	if f.ScanUUID != "" {
		m["scan_uuid"] = f.ScanUUID
	}
	if f.ModuleType != "" {
		m["module_type"] = f.ModuleType
	}
	if f.FindingSource != "" {
		m["finding_source"] = f.FindingSource
	}
	if f.ModuleShort != "" {
		m["module_short"] = f.ModuleShort
	}
	return m
}

func findingsToJS(vm *sobek.Runtime, findings []*database.Finding) sobek.Value {
	arr := make([]interface{}, len(findings))
	for i, f := range findings {
		arr[i] = findingToMap(f)
	}
	return vm.ToValue(arr)
}

// jsToQueryFilters parses a JS filters object into database.QueryFilters.
func jsToQueryFilters(vm *sobek.Runtime, v sobek.Value) database.QueryFilters {
	var f database.QueryFilters
	if v == nil || sobek.IsUndefined(v) || sobek.IsNull(v) {
		return f
	}
	obj := v.ToObject(vm)

	if val := obj.Get("hostname"); val != nil && !sobek.IsUndefined(val) {
		f.HostPattern = val.String()
	}
	if val := obj.Get("path"); val != nil && !sobek.IsUndefined(val) {
		f.PathPattern = val.String()
	}
	if val := obj.Get("methods"); val != nil && !sobek.IsUndefined(val) && !sobek.IsNull(val) {
		raw, _ := json.Marshal(val.Export())
		_ = json.Unmarshal(raw, &f.Methods)
	}
	if val := obj.Get("status_codes"); val != nil && !sobek.IsUndefined(val) && !sobek.IsNull(val) {
		raw, _ := json.Marshal(val.Export())
		_ = json.Unmarshal(raw, &f.StatusCodes)
	}
	if val := obj.Get("source"); val != nil && !sobek.IsUndefined(val) {
		f.Source = val.String()
	}
	if val := obj.Get("search"); val != nil && !sobek.IsUndefined(val) {
		f.SearchTerm = val.String()
	}
	if val := obj.Get("fuzzy"); val != nil && !sobek.IsUndefined(val) {
		f.FuzzyTerm = val.String()
	}
	if val := obj.Get("min_risk_score"); val != nil && !sobek.IsUndefined(val) {
		f.MinRiskScore = int(val.ToInteger())
	}
	if val := obj.Get("remark"); val != nil && !sobek.IsUndefined(val) {
		f.Remark = val.String()
	}
	if val := obj.Get("remarks"); val != nil && !sobek.IsUndefined(val) && !sobek.IsNull(val) {
		raw, _ := json.Marshal(val.Export())
		_ = json.Unmarshal(raw, &f.Remarks)
	}
	if val := obj.Get("limit"); val != nil && !sobek.IsUndefined(val) {
		f.Limit = int(val.ToInteger())
	}
	if val := obj.Get("offset"); val != nil && !sobek.IsUndefined(val) {
		f.Offset = int(val.ToInteger())
	}
	if val := obj.Get("sort_by"); val != nil && !sobek.IsUndefined(val) {
		f.SortBy = val.String()
	}
	if val := obj.Get("sort_asc"); val != nil && !sobek.IsUndefined(val) {
		f.SortAsc = val.ToBoolean()
	}
	if val := obj.Get("severity"); val != nil && !sobek.IsUndefined(val) && !sobek.IsNull(val) {
		raw, _ := json.Marshal(val.Export())
		_ = json.Unmarshal(raw, &f.Severity)
	}
	if val := obj.Get("module_name"); val != nil && !sobek.IsUndefined(val) {
		f.ModuleName = val.String()
	}
	if val := obj.Get("module_type"); val != nil && !sobek.IsUndefined(val) {
		f.ModuleType = val.String()
	}
	if val := obj.Get("finding_source"); val != nil && !sobek.IsUndefined(val) {
		f.FindingSource = val.String()
	}
	if val := obj.Get("scan_uuid"); val != nil && !sobek.IsUndefined(val) {
		f.ScanUUID = val.String()
	}
	return f
}

// jsToFinding parses a JS object into a database.Finding.
// Returns nil if required fields (module_id, module_name) are missing.
func jsToFinding(vm *sobek.Runtime, obj *sobek.Object) *database.Finding {
	moduleID := stringField(vm, obj, "module_id", "")
	moduleName := stringField(vm, obj, "module_name", "")
	if moduleID == "" || moduleName == "" {
		return nil
	}

	f := &database.Finding{
		ProjectUUID:   stringField(vm, obj, "project_uuid", ""),
		ModuleID:      moduleID,
		ModuleName:    moduleName,
		Severity:      stringField(vm, obj, "severity", "info"),
		Confidence:    stringField(vm, obj, "confidence", "firm"),
		Description:   stringField(vm, obj, "description", ""),
		Request:       stringField(vm, obj, "request", ""),
		Response:      stringField(vm, obj, "response", ""),
		FindingHash:   stringField(vm, obj, "finding_hash", ""),
		ScanUUID:      stringField(vm, obj, "scan_uuid", ""),
		ModuleType:    stringField(vm, obj, "module_type", database.ModuleTypeExtension),
		FindingSource: stringField(vm, obj, "finding_source", database.FindingSourceExtension),
		ModuleShort:   stringField(vm, obj, "module_short", ""),
		FoundAt:       time.Now(),
	}

	if v := obj.Get("matched_at"); v != nil && !sobek.IsUndefined(v) && !sobek.IsNull(v) {
		raw, _ := json.Marshal(v.Export())
		_ = json.Unmarshal(raw, &f.MatchedAt)
	}
	if v := obj.Get("extracted_results"); v != nil && !sobek.IsUndefined(v) && !sobek.IsNull(v) {
		raw, _ := json.Marshal(v.Export())
		_ = json.Unmarshal(raw, &f.ExtractedResults)
	}
	if v := obj.Get("tags"); v != nil && !sobek.IsUndefined(v) && !sobek.IsNull(v) {
		raw, _ := json.Marshal(v.Export())
		_ = json.Unmarshal(raw, &f.Tags)
	}
	if v := obj.Get("additional_evidence"); v != nil && !sobek.IsUndefined(v) && !sobek.IsNull(v) {
		raw, _ := json.Marshal(v.Export())
		_ = json.Unmarshal(raw, &f.AdditionalEvidence)
	}
	if v := obj.Get("http_record_uuids"); v != nil && !sobek.IsUndefined(v) && !sobek.IsNull(v) {
		raw, _ := json.Marshal(v.Export())
		_ = json.Unmarshal(raw, &f.HTTPRecordUUIDs)
	}
	if f.HTTPRecordUUIDs == nil {
		f.HTTPRecordUUIDs = []string{}
	}
	return f
}
