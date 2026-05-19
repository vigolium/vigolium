package jsext

import (
	"github.com/grafana/sobek"
)

// EvalResult holds the output of an evaluated script.
type EvalResult struct {
	Value string // JSON-stringified return value ("" if undefined/null)
	Error error
}

// Eval runs arbitrary JS code in a fresh VM with vigolium.* APIs installed.
// If the script returns a non-undefined/null value, it is JSON-stringified.
func Eval(source string, opts APIOptions) EvalResult {
	vm := sobek.New()

	// Set up module.exports (CommonJS compat)
	exports := vm.NewObject()
	module := vm.NewObject()
	_ = module.Set("exports", exports)
	_ = vm.Set("module", module)
	_ = vm.Set("exports", exports)

	// Install vigolium.* APIs
	SetupAPI(vm, opts)

	// Execute the script
	val, err := vm.RunString(source)
	if err != nil {
		return EvalResult{Error: err}
	}

	// If result is undefined or null, return empty value
	if val == nil || sobek.IsUndefined(val) || sobek.IsNull(val) {
		return EvalResult{}
	}

	// JSON.stringify the return value
	stringify, err := vm.RunString("JSON.stringify")
	if err != nil {
		return EvalResult{Error: err}
	}

	fn, ok := sobek.AssertFunction(stringify)
	if !ok {
		return EvalResult{Value: val.String()}
	}

	jsonVal, err := fn(sobek.Undefined(), val)
	if err != nil {
		return EvalResult{Value: val.String()}
	}

	return EvalResult{Value: jsonVal.String()}
}
