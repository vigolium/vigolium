package jsext

import (
	"github.com/grafana/sobek"
)

// SetupAPI installs the vigolium.* global namespace on a sobek VM.
func SetupAPI(vm *sobek.Runtime, opts APIOptions) {
	// Create top-level vigolium object
	vigolium := vm.NewObject()
	_ = vm.Set("vigolium", vigolium)

	// Set up config variables
	configObj := vm.NewObject()
	for k, v := range opts.ConfigVars {
		_ = configObj.Set(k, v)
	}
	_ = vigolium.Set("config", configObj)

	// Register all functions via the declarative registry
	registerFuncs(vm, opts, allFuncDefs())
}
