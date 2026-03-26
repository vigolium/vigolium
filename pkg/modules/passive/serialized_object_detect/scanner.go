package serialized_object_detect

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/utils"
	"github.com/pkg/errors"
)

// Serialization format detection patterns.
var phpSerializeRe = regexp.MustCompile(`^[OaCsbi]:\d+[:{]`)

const (
	javaBase64Prefix  = "rO0AB"
	javaHexPrefix     = "aced0005"
	dotnetBase64Prefix = "AAEAAAD"
)

// Module implements the Serialized Object Detection passive scanner.
type Module struct {
	modkit.BasePassiveModule
	rhm dedup.Lazy[dedup.RequestHashManager]
}

// New creates a new Serialized Object Detection module.
func New() *Module {
	m := &Module{
		BasePassiveModule: modkit.NewBasePassiveModule(
			ModuleID,
			ModuleName,
			ModuleDesc,
			ModuleShort,
			ModuleConfirmation,
			ModuleSeverity,
			ModuleConfidence,
			modkit.ScanScopeRequest,
			modkit.PassiveScanScopeRequest,
		),
		rhm: dedup.LazyDefaultRHM("passive_serialized_object_detect"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerRequest checks request parameters for serialized object signatures.
func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	if utils.IsMediaAndJSURL(urlx.Path) {
		return nil, nil
	}

	params, err := ctx.Request().Parameters()
	if err != nil || len(params) == 0 {
		return nil, nil
	}

	rhm := m.rhm.Get(scanCtx.DedupMgr())

	var results []*output.ResultEvent
	for _, param := range params {
		value := param.Value()
		if len(value) == 0 {
			continue
		}

		formatName := detectFormat(value)
		if formatName == "" {
			continue
		}

		if rhm != nil && !rhm.ShouldCheck3(urlx, ctx.Request().Method(), ctx.Request().BodyToString(), param.Name(), "", formatName) {
			continue
		}

		results = append(results, &output.ResultEvent{
			ModuleID:         ModuleID,
			Host:             urlx.Host,
			URL:              urlx.String(),
			Matched:          urlx.String(),
			FuzzingParameter: param.Name(),
			Request:          string(ctx.Request().Raw()),
			ExtractedResults: []string{
				fmt.Sprintf("Format: %s", formatName),
				fmt.Sprintf("Parameter: %s", param.Name()),
				fmt.Sprintf("Value (truncated): %s", truncate(value, 80)),
			},
			Info: output.Info{
				Name:        fmt.Sprintf("Serialized %s Object in Parameter", formatName),
				Description: fmt.Sprintf("Parameter %q contains a %s serialized object", param.Name(), formatName),
			},
		})
	}

	return results, nil
}

// detectFormat checks if a value matches known serialization signatures.
func detectFormat(value string) string {
	if strings.HasPrefix(value, javaBase64Prefix) {
		return "Java"
	}

	lower := strings.ToLower(value)
	if strings.HasPrefix(lower, javaHexPrefix) {
		return "Java"
	}

	if len(value) >= 2 && value[0] == 0xAC && value[1] == 0xED {
		return "Java"
	}

	// PHP: O:N:"class", a:N:{, s:N:", etc.
	if phpSerializeRe.MatchString(value) {
		return "PHP"
	}

	// .NET: base64 prefix "AAEAAAD" (BinaryFormatter)
	if strings.HasPrefix(value, dotnetBase64Prefix) {
		return ".NET"
	}

	// Python: pickle indicators
	if strings.HasPrefix(value, "ccopy_reg") || strings.HasPrefix(value, "ccopyreg") {
		return "Python"
	}
	if len(value) >= 1 && value[0] == 0x80 {
		return "Python"
	}

	return ""
}

// truncate returns the first n characters of s, appending "..." if truncated.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
