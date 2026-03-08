package jsext

import (
	"fmt"

	"github.com/evanw/esbuild/pkg/api"
)

// TranspileTS converts TypeScript source to JavaScript using esbuild.
// It strips type annotations, handles interfaces/enums/generics, and outputs
// CommonJS-format JS compatible with the sobek runtime.
func TranspileTS(source string, filename string) (string, error) {
	result := api.Transform(source, api.TransformOptions{
		Loader:     api.LoaderTS,
		Target:     api.ES2020,
		Format:     api.FormatCommonJS,
		Sourcefile: filename,
	})
	if len(result.Errors) > 0 {
		return "", fmt.Errorf("TypeScript transpile error in %s: %s", filename, result.Errors[0].Text)
	}
	return string(result.Code), nil
}
