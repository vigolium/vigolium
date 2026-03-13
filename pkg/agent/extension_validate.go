package agent

import (
	"fmt"
	"strings"

	"github.com/grafana/sobek"
	"go.uber.org/zap"
)

// ValidateExtensionSyntax compiles each extension's JavaScript code for
// parse-only validation and returns only the extensions that parse
// successfully. Invalid or empty extensions are logged and dropped.
func ValidateExtensionSyntax(extensions []GeneratedExtension) []GeneratedExtension {
	valid := make([]GeneratedExtension, 0, len(extensions))
	for _, ext := range extensions {
		if strings.TrimSpace(ext.Code) == "" {
			zap.L().Warn("Dropping invalid extension",
				zap.String("filename", ext.Filename),
				zap.Error(fmt.Errorf("empty code")))
			continue
		}
		_, err := sobek.Compile(ext.Filename, ext.Code, false)
		if err != nil {
			zap.L().Warn("Dropping invalid extension",
				zap.String("filename", ext.Filename),
				zap.Error(err))
			continue
		}
		valid = append(valid, ext)
	}
	return valid
}

// deduplicateExtensionFilename returns a filename that does not collide with
// any key already present in existing. On collision it strips the .js suffix,
// appends -2, -3, … until a unique name is found, and re-adds .js.
func deduplicateExtensionFilename(name string, existing map[string]bool) string {
	if !existing[name] {
		return name
	}
	base := strings.TrimSuffix(name, ".js")
	for i := 2; ; i++ {
		candidate := fmt.Sprintf("%s-%d.js", base, i)
		if !existing[candidate] {
			return candidate
		}
	}
}
