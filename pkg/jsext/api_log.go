package jsext

import (
	"github.com/grafana/sobek"
	"go.uber.org/zap"
)

// setupLogAPI registers vigolium.log.* functions on the VM.
func setupLogAPI(vm *sobek.Runtime, scriptID string) {
	logObj := vm.NewObject()

	logger := zap.L().With(zap.String("ext", scriptID))

	_ = logObj.Set("info", func(call sobek.FunctionCall) sobek.Value {
		msg := call.Argument(0).String()
		logger.Info(msg)
		return sobek.Undefined()
	})

	_ = logObj.Set("warn", func(call sobek.FunctionCall) sobek.Value {
		msg := call.Argument(0).String()
		logger.Warn(msg)
		return sobek.Undefined()
	})

	_ = logObj.Set("error", func(call sobek.FunctionCall) sobek.Value {
		msg := call.Argument(0).String()
		logger.Error(msg)
		return sobek.Undefined()
	})

	_ = logObj.Set("debug", func(call sobek.FunctionCall) sobek.Value {
		msg := call.Argument(0).String()
		logger.Debug(msg)
		return sobek.Undefined()
	})

	vigolium := vm.Get("vigolium").ToObject(vm)
	_ = vigolium.Set("log", logObj)
}
