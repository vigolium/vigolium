package jsext

import (
	"github.com/grafana/sobek"
	"go.uber.org/zap"
)

// logFuncDefs returns the JSFuncDef entries for vigolium.log.*.
func logFuncDefs() []JSFuncDef {
	return []JSFuncDef{
		{
			Namespace: NsLog, Name: "info",
			Category: CatLogging, Signature: ".info(msg: string)", Returns: "void",
			Description: "Log an informational message.", Example: exLogInfo,
			MakeHandler: func(vm *sobek.Runtime, opts APIOptions) func(sobek.FunctionCall) sobek.Value {
				logger := zap.L().With(zap.String("ext", opts.ScriptID))
				return func(call sobek.FunctionCall) sobek.Value {
					logger.Info(call.Argument(0).String())
					return sobek.Undefined()
				}
			},
		},
		{
			Namespace: NsLog, Name: "warn",
			Category: CatLogging, Signature: ".warn(msg: string)", Returns: "void",
			Description: "Log a warning message.", Example: exLogWarn,
			MakeHandler: func(vm *sobek.Runtime, opts APIOptions) func(sobek.FunctionCall) sobek.Value {
				logger := zap.L().With(zap.String("ext", opts.ScriptID))
				return func(call sobek.FunctionCall) sobek.Value {
					logger.Warn(call.Argument(0).String())
					return sobek.Undefined()
				}
			},
		},
		{
			Namespace: NsLog, Name: "error",
			Category: CatLogging, Signature: ".error(msg: string)", Returns: "void",
			Description: "Log an error message.", Example: exLogError,
			MakeHandler: func(vm *sobek.Runtime, opts APIOptions) func(sobek.FunctionCall) sobek.Value {
				logger := zap.L().With(zap.String("ext", opts.ScriptID))
				return func(call sobek.FunctionCall) sobek.Value {
					logger.Error(call.Argument(0).String())
					return sobek.Undefined()
				}
			},
		},
		{
			Namespace: NsLog, Name: "debug",
			Category: CatLogging, Signature: ".debug(msg: string)", Returns: "void",
			Description: "Log a debug message (only visible at debug log level).", Example: exLogDebug,
			MakeHandler: func(vm *sobek.Runtime, opts APIOptions) func(sobek.FunctionCall) sobek.Value {
				logger := zap.L().With(zap.String("ext", opts.ScriptID))
				return func(call sobek.FunctionCall) sobek.Value {
					logger.Debug(call.Argument(0).String())
					return sobek.Undefined()
				}
			},
		},
	}
}
