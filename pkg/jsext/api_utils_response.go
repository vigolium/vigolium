package jsext

import (
	"math"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"github.com/grafana/sobek"
)

// responseUtilsFuncDefs returns the JSFuncDef entries for response comparison and CSS selector utilities in vigolium.utils.*.
func responseUtilsFuncDefs() []JSFuncDef {
	return []JSFuncDef{
		{
			Namespace: NsUtils, Name: "diffResponses",
			Category: "Utils", Signature: ".diffResponses(a: object, b: object)", Returns: "object | null",
			Description: "Compare two HTTP response objects and return a detailed diff.", Example: "",
			MakeHandler: func(vm *sobek.Runtime, opts APIOptions) func(sobek.FunctionCall) sobek.Value {
				return func(call sobek.FunctionCall) sobek.Value {
					aVal := call.Argument(0)
					bVal := call.Argument(1)

					if sobek.IsUndefined(aVal) || sobek.IsNull(aVal) ||
						sobek.IsUndefined(bVal) || sobek.IsNull(bVal) {
						return sobek.Null()
					}

					aObj := aVal.ToObject(vm)
					bObj := bVal.ToObject(vm)

					// Extract status codes
					aStatus := 0
					bStatus := 0
					if v := aObj.Get("status"); v != nil && !sobek.IsUndefined(v) {
						aStatus = int(v.ToInteger())
					}
					if v := bObj.Get("status"); v != nil && !sobek.IsUndefined(v) {
						bStatus = int(v.ToInteger())
					}

					// Extract bodies
					aBody := ""
					bBody := ""
					if v := aObj.Get("body"); v != nil && !sobek.IsUndefined(v) {
						aBody = v.String()
					}
					if v := bObj.Get("body"); v != nil && !sobek.IsUndefined(v) {
						bBody = v.String()
					}

					// Extract headers
					aHeaders := extractHeaderMap(vm, aObj)
					bHeaders := extractHeaderMap(vm, bObj)

					// Status comparison
					statusMatch := aStatus == bStatus

					// Body similarity (Jaccard on words)
					bodySimilarity := jaccardSimilarity(aBody, bBody)

					// Header diff
					var headerAdded, headerRemoved, headerChanged []interface{}
					for k, v := range bHeaders {
						aVal, exists := aHeaders[k]
						if !exists {
							headerAdded = append(headerAdded, k)
						} else if aVal != v {
							headerChanged = append(headerChanged, k)
						}
					}
					for k := range aHeaders {
						if _, exists := bHeaders[k]; !exists {
							headerRemoved = append(headerRemoved, k)
						}
					}

					// Body diff (line-level)
					aLines := strings.Split(aBody, "\n")
					bLines := strings.Split(bBody, "\n")
					aLineSet := make(map[string]bool, len(aLines))
					bLineSet := make(map[string]bool, len(bLines))
					for _, l := range aLines {
						aLineSet[l] = true
					}
					for _, l := range bLines {
						bLineSet[l] = true
					}

					var bodyAdded, bodyRemoved []interface{}
					for _, l := range bLines {
						if !aLineSet[l] && l != "" {
							bodyAdded = append(bodyAdded, l)
						}
					}
					for _, l := range aLines {
						if !bLineSet[l] && l != "" {
							bodyRemoved = append(bodyRemoved, l)
						}
					}

					// Length diff
					lengthDiff := len(bBody) - len(aBody)

					// Heuristic: likely same content if same status class + high similarity
					likelySameContent := false
					if aStatus > 0 && bStatus > 0 {
						sameStatusClass := (aStatus / 100) == (bStatus / 100)
						likelySameContent = sameStatusClass && bodySimilarity > 0.85
					}

					// Build result
					if headerAdded == nil {
						headerAdded = []interface{}{}
					}
					if headerRemoved == nil {
						headerRemoved = []interface{}{}
					}
					if headerChanged == nil {
						headerChanged = []interface{}{}
					}
					if bodyAdded == nil {
						bodyAdded = []interface{}{}
					}
					if bodyRemoved == nil {
						bodyRemoved = []interface{}{}
					}

					headerDiff := vm.NewObject()
					_ = headerDiff.Set("added", vm.ToValue(headerAdded))
					_ = headerDiff.Set("removed", vm.ToValue(headerRemoved))
					_ = headerDiff.Set("changed", vm.ToValue(headerChanged))

					bodyDiff := vm.NewObject()
					_ = bodyDiff.Set("added", vm.ToValue(bodyAdded))
					_ = bodyDiff.Set("removed", vm.ToValue(bodyRemoved))

					result := vm.NewObject()
					_ = result.Set("status_match", statusMatch)
					_ = result.Set("body_similarity", math.Round(bodySimilarity*1000)/1000)
					_ = result.Set("header_diff", headerDiff)
					_ = result.Set("body_diff", bodyDiff)
					_ = result.Set("length_diff", lengthDiff)
					_ = result.Set("likely_same_content", likelySameContent)
					return result
				}
			},
		},
		{
			Namespace: NsUtils, Name: "cssSelect",
			Category: "Utils", Signature: ".cssSelect(html: string, selector: string)", Returns: "object[]",
			Description: "Extract elements from HTML using a CSS selector.", Example: "",
			MakeHandler: func(vm *sobek.Runtime, opts APIOptions) func(sobek.FunctionCall) sobek.Value {
				return func(call sobek.FunctionCall) sobek.Value {
					htmlStr := call.Argument(0).String()
					selector := call.Argument(1).String()

					if htmlStr == "" || selector == "" {
						return vm.NewArray()
					}

					// Cap input at 2MB
					const maxSize = 2 << 20
					if len(htmlStr) > maxSize {
						htmlStr = htmlStr[:maxSize]
					}

					doc, err := goquery.NewDocumentFromReader(strings.NewReader(htmlStr))
					if err != nil {
						return vm.NewArray()
					}

					var results []interface{}
					doc.Find(selector).Each(func(i int, s *goquery.Selection) {
						// Cap at 100 results
						if len(results) >= 100 {
							return
						}

						elem := vm.NewObject()
						_ = elem.Set("text", strings.TrimSpace(s.Text()))

						// Collect attributes
						attrs := vm.NewObject()
						if s.Length() > 0 {
							for _, attr := range s.Get(0).Attr {
								_ = attrs.Set(attr.Key, attr.Val)
							}
						}
						_ = elem.Set("attrs", attrs)

						// Also expose inner HTML
						innerHtml, _ := s.Html()
						_ = elem.Set("html", innerHtml)

						results = append(results, elem)
					})

					if results == nil {
						results = []interface{}{}
					}
					return vm.ToValue(results)
				}
			},
		},
	}
}

// extractHeaderMap pulls all headers from a response JS object into a Go map.
func extractHeaderMap(vm *sobek.Runtime, obj *sobek.Object) map[string]string {
	result := make(map[string]string)
	v := obj.Get("headers")
	if v == nil || sobek.IsUndefined(v) || sobek.IsNull(v) {
		return result
	}
	headersObj := v.ToObject(vm)
	for _, key := range headersObj.Keys() {
		result[key] = headersObj.Get(key).String()
	}
	return result
}
