package jsext

import (
	"github.com/grafana/sobek"

	"github.com/vigolium/vigolium/pkg/payloads"
)

// payloadsFuncDefs returns declarative definitions for vigolium.payloads().
// Returns built-in payload wordlists by vulnerability type.
func payloadsFuncDefs() []JSFuncDef {
	return []JSFuncDef{
		{
			Namespace: NsRoot, Name: "payloads",
			Category: "Payloads", Signature: ".payloads(type: string)", Returns: "string[]",
			Description: "Returns built-in payload wordlists by vulnerability type (xss, sqli, ssti, ssrf, lfi, path_traversal, xxe, cmdi, open_redirect, crlf).",
			Example:     "",
			MakeHandler: func(vm *sobek.Runtime, opts APIOptions) func(sobek.FunctionCall) sobek.Value {
				return func(call sobek.FunctionCall) sobek.Value {
					vulnType := call.Argument(0).String()
					list, ok := payloads.ByClass(vulnType)
					if !ok {
						return vm.NewArray()
					}
					result := make([]interface{}, len(list))
					for i, p := range list {
						result[i] = p
					}
					return vm.ToValue(result)
				}
			},
		},
	}
}
