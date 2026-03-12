package jsext

import (
	"context"
	"fmt"
	"strings"

	"github.com/grafana/sobek"
	"github.com/vigolium/vigolium/pkg/database"
	"go.uber.org/zap"
)

// dbGroupedFuncDefs returns the JSFuncDef entries for vigolium.db.records.grouped.
func dbGroupedFuncDefs() []JSFuncDef {
	return []JSFuncDef{
		{
			Namespace: NsDBRecords, Name: "grouped",
			Category:    CatDBRecords,
			Signature:   ".grouped(opts?: {hostname?, min_group_size?, methods?})",
			Returns:     "RecordGroup[]",
			Description: "Group HTTP records by method and path template. Returns groups with at least min_group_size records (default 2).",
			Example:     `var groups = vigolium.db.records.grouped({hostname: "example.com", min_group_size: 3})`,
			MakeHandler: func(vm *sobek.Runtime, opts APIOptions) func(sobek.FunctionCall) sobek.Value {
				repo := opts.Repository
				return func(call sobek.FunctionCall) sobek.Value {
					hostname := ""
					minGroupSize := 2
					var methods []string

					if optsVal := call.Argument(0); optsVal != nil && !sobek.IsUndefined(optsVal) && !sobek.IsNull(optsVal) {
						optsObj := optsVal.ToObject(vm)
						if v := optsObj.Get("hostname"); v != nil && !sobek.IsUndefined(v) {
							hostname = v.String()
						}
						if v := optsObj.Get("min_group_size"); v != nil && !sobek.IsUndefined(v) {
							ms := int(v.ToInteger())
							if ms > 0 {
								minGroupSize = ms
							}
						}
						if v := optsObj.Get("methods"); v != nil && !sobek.IsUndefined(v) && !sobek.IsNull(v) {
							methodsArr := v.ToObject(vm)
							length := int(methodsArr.Get("length").ToInteger())
							for i := range length {
								methods = append(methods, strings.ToUpper(methodsArr.Get(fmt.Sprintf("%d", i)).String()))
							}
						}
					}

					// Query records
					filters := database.QueryFilters{
						HostPattern: hostname,
						Methods:     methods,
						Limit:       5000, // cap to avoid OOM
					}
					qb := database.NewQueryBuilder(repo.DB(), filters)
					records, err := qb.Execute(context.Background())
					if err != nil {
						zap.L().Debug("db.records.grouped: query failed", zap.Error(err))
						return vm.NewArray()
					}

					if len(records) == 0 {
						return vm.NewArray()
					}

					// Group by (method, path_template)
					type groupKey struct {
						method   string
						template string
					}
					type recordGroup struct {
						template    string
						method      string
						records     []*database.HTTPRecord
						paramValues [][]string
					}

					groups := make(map[groupKey]*recordGroup)
					groupOrder := make([]groupKey, 0)

					for _, r := range records {
						tmpl := database.PathToTemplate(r.Path)
						key := groupKey{method: r.Method, template: tmpl}

						g, exists := groups[key]
						if !exists {
							g = &recordGroup{
								template: tmpl,
								method:   r.Method,
							}
							groups[key] = g
							groupOrder = append(groupOrder, key)
						}
						g.records = append(g.records, r)

						// Extract dynamic segment values
						dynValues := extractDynamicValues(r.Path, tmpl)
						g.paramValues = append(g.paramValues, dynValues)
					}

					// Filter by min_group_size and build JS result
					var results []interface{}
					for _, key := range groupOrder {
						g := groups[key]
						if len(g.records) < minGroupSize {
							continue
						}

						recordsJS := make([]interface{}, len(g.records))
						for i, r := range g.records {
							recordsJS[i] = httpRecordToMap(r)
						}

						paramValuesJS := make([]interface{}, len(g.paramValues))
						for i, pv := range g.paramValues {
							vals := make([]interface{}, len(pv))
							for j, v := range pv {
								vals[j] = v
							}
							paramValuesJS[i] = vals
						}

						results = append(results, map[string]interface{}{
							"template":     g.template,
							"method":       g.method,
							"records":      recordsJS,
							"param_values": paramValuesJS,
						})
					}

					if len(results) == 0 {
						return vm.NewArray()
					}
					return vm.ToValue(results)
				}
			},
		},
	}
}

// extractDynamicValues compares an original path against its template and returns the values
// at positions where the template has "*".
func extractDynamicValues(path, template string) []string {
	pathParts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	tmplParts := strings.Split(strings.TrimPrefix(template, "/"), "/")

	var values []string
	for i, tp := range tmplParts {
		if tp == "*" && i < len(pathParts) {
			values = append(values, pathParts[i])
		}
	}
	return values
}
