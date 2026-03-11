package jsext

import (
	"context"
	"time"

	"github.com/grafana/sobek"
	"go.uber.org/zap"
)

// setupOASTAPI registers vigolium.oast.* functions on the VM.
// Provides out-of-band testing capabilities via interactsh.
func setupOASTAPI(vm *sobek.Runtime, opts APIOptions) {
	oastObj := vm.NewObject()

	svc := opts.OASTService

	// vigolium.oast.enabled() -> boolean
	_ = oastObj.Set("enabled", func(call sobek.FunctionCall) sobek.Value {
		return vm.ToValue(svc != nil && svc.Enabled())
	})

	// vigolium.oast.payload(targetURL?, paramName?, injectionType?) -> {url, id} | null
	// Generates a unique OAST callback URL for out-of-band testing.
	_ = oastObj.Set("payload", func(call sobek.FunctionCall) sobek.Value {
		if svc == nil || !svc.Enabled() {
			return sobek.Null()
		}

		targetURL := ""
		paramName := ""
		injectionType := "extension"
		if v := call.Argument(0); !sobek.IsUndefined(v) {
			targetURL = v.String()
		}
		if v := call.Argument(1); !sobek.IsUndefined(v) {
			paramName = v.String()
		}
		if v := call.Argument(2); !sobek.IsUndefined(v) {
			injectionType = v.String()
		}

		url := svc.GenerateURL(targetURL, paramName, injectionType, "ext-"+opts.ScriptID, "")
		if url == "" {
			return sobek.Null()
		}

		result := vm.NewObject()
		_ = result.Set("url", url)
		return result
	})

	// vigolium.oast.poll(timeoutMs?) -> OASTInteraction[]
	// Waits for the specified timeout then queries for OAST interactions from the current scan.
	_ = oastObj.Set("poll", func(call sobek.FunctionCall) sobek.Value {
		if svc == nil || !svc.Enabled() {
			return vm.NewArray()
		}

		timeoutMs := int64(5000) // default 5s
		if v := call.Argument(0); !sobek.IsUndefined(v) {
			timeoutMs = v.ToInteger()
		}
		if timeoutMs > 30000 {
			timeoutMs = 30000 // cap at 30s
		}
		if timeoutMs > 0 {
			time.Sleep(time.Duration(timeoutMs) * time.Millisecond)
		}

		// Query OAST interactions from the database
		if opts.Repository == nil || opts.ScanUUID == "" {
			return vm.NewArray()
		}

		interactions, err := opts.Repository.GetOASTInteractionsByScan(context.Background(), opts.ScanUUID)
		if err != nil {
			zap.L().Debug("OAST poll: failed to query interactions", zap.Error(err))
			return vm.NewArray()
		}

		if len(interactions) == 0 {
			return vm.NewArray()
		}

		results := make([]interface{}, 0, len(interactions))
		for _, ix := range interactions {
			obj := vm.NewObject()
			_ = obj.Set("protocol", ix.Protocol)
			_ = obj.Set("unique_id", ix.UniqueID)
			_ = obj.Set("full_id", ix.FullID)
			_ = obj.Set("remote_address", ix.RemoteAddress)
			_ = obj.Set("target_url", ix.TargetURL)
			_ = obj.Set("parameter_name", ix.ParameterName)
			_ = obj.Set("module_id", ix.ModuleID)
			_ = obj.Set("interacted_at", ix.InteractedAt.Format(time.RFC3339))
			results = append(results, obj)
		}

		return vm.ToValue(results)
	})

	vigolium := vm.Get("vigolium").ToObject(vm)
	_ = vigolium.Set("oast", oastObj)
}
