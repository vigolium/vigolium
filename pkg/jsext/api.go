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

	// Set up sub-APIs
	setupLogAPI(vm, opts.ScriptID)
	setupUtilsAPI(vm, opts)
	setupParseAPI(vm)
	if opts.HTTPClient != nil {
		setupHTTPAPI(vm, opts.HTTPClient)
	}

	// Set up scan API when scanner context is available
	setupScanAPI(vm, opts)

	// Set up ingest API when repository is available
	if opts.Repository != nil {
		setupIngestAPI(vm, opts)
	}

	// Set up source API when repository is available
	if opts.Repository != nil {
		setupSourceAPI(vm, opts)
	}

	// Set up agent API when LLM client is available
	if opts.LLMClient != nil {
		setupAgentAPI(vm, opts)
	}

	// Set up database API when repository is available
	if opts.Repository != nil {
		setupDBAPI(vm, opts)
	}

	// Set up OAST API when service is available
	if opts.OASTService != nil {
		setupOASTAPI(vm, opts)
	}

	// Set up built-in payload wordlists
	setupPayloadsAPI(vm)
}
