package serialized_object_detect

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/utils"
)

// Serialization format detection patterns.
var phpSerializeRe = regexp.MustCompile(`^[OaCsbi]:\d+[:{]`)

const (
	javaBase64Prefix   = "rO0AB"
	javaHexPrefix      = "aced0005"
	dotnetBase64Prefix = "AAEAAAD"

	// nodeSerializeMarker is the function token emitted by the node-serialize
	// library. Its presence in a payload is what enables RCE via the
	// unserialize() immediately-invoked-function trick, so it can appear
	// anywhere inside the (JSON) value rather than as a prefix.
	nodeSerializeMarker = "_$$ND_FUNC$$_"
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

// detectFormat checks if a value carries a serialized object. It first inspects
// the raw value, then makes a single base64-decode pass so that base64-wrapped
// payloads — the common transport form in cookies and URL/body parameters — are
// caught too. A finding is only raised when the decoded bytes match a real
// signature, so loose decodes of benign strings produce nothing.
func detectFormat(value string) string {
	if f := detectRawFormat(value); f != "" {
		return f
	}
	if decoded, ok := tryBase64Decode(value); ok {
		if f := detectRawFormat(decoded); f != "" {
			return f + " (base64-wrapped)"
		}
	}
	return ""
}

// detectRawFormat matches known serialization signatures against the literal
// bytes of value (no decoding).
func detectRawFormat(value string) string {
	// Node.js node-serialize: the function marker can appear anywhere in the
	// JSON value, not just as a prefix.
	if strings.Contains(value, nodeSerializeMarker) {
		return "Node.js"
	}

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

	// Ruby Marshal: the stream always begins with the version header 0x04 0x08
	// (major 4, minor 8). Mirrors the 2-byte Java magic check above.
	if len(value) >= 2 && value[0] == 0x04 && value[1] == 0x08 {
		return "Ruby"
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
	// pickle PROTO opcode (0x80) followed by a protocol version byte (2-5).
	// Requiring the version byte avoids flagging arbitrary binary that merely
	// starts with 0x80.
	if len(value) >= 2 && value[0] == 0x80 && value[1] >= 0x02 && value[1] <= 0x05 {
		return "Python"
	}

	return ""
}

// tryBase64Decode attempts to decode value as base64 (standard or URL-safe,
// padded or not). It returns ok only when the value cleanly decodes; the
// signature recheck in detectFormat is what actually gates findings, so a
// successful decode of a benign string is harmless on its own.
func tryBase64Decode(value string) (string, bool) {
	// Too short to plausibly carry a serialized object, and short strings are
	// far more likely to be coincidentally-valid base64.
	if len(value) < 8 {
		return "", false
	}
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	} {
		if decoded, err := enc.DecodeString(value); err == nil && len(decoded) > 0 {
			return string(decoded), true
		}
	}
	return "", false
}

// truncate returns the first n characters of s, appending "..." if truncated.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
