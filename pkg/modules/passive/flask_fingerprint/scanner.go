package flask_fingerprint

import (
	"strings"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// Module implements the Flask Fingerprint passive scanner.
type Module struct {
	modkit.BasePassiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new Flask Fingerprint module.
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
			modkit.PassiveScanScopeResponse,
		),
		ds: dedup.LazyDiskSet("flask_fingerprint"),
	}
	m.ModuleTags = ModuleTags
	return m
}

func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	if !ctx.HasResponse() {
		return nil, nil
	}

	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	host := urlx.Host
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	if diskSet != nil && diskSet.IsSeen(host) {
		return nil, nil
	}

	hdr := func(name string) string { return ctx.Response().Header(name) }
	body := ctx.Response().BodyToString()

	var extracted []string
	meta := map[string]any{
		"platform": "flask",
	}

	hasStrongSignal := false
	weakSignalCount := 0

	// STRONG Signal 1: Response body contains "Werkzeug Debugger" or "werkzeug"
	if strings.Contains(body, "Werkzeug Debugger") || strings.Contains(body, "werkzeug") {
		hasStrongSignal = true
		extracted = append(extracted, "Body: Werkzeug Debugger detected")
		meta["hasDebugger"] = true
	}

	// STRONG Signal 2: Server header contains "Werkzeug"
	serverHdr := hdr("Server")
	if strings.Contains(serverHdr, "Werkzeug") {
		hasStrongSignal = true
		extracted = append(extracted, "Server: "+serverHdr)
		meta["server"] = "werkzeug"
	}

	// Weak Signal 3: Set-Cookie name starts with "session=" AND value starts with "eyJ"
	for _, h := range ctx.Response().Headers() {
		if !strings.EqualFold(h.Name, "Set-Cookie") {
			continue
		}
		if strings.HasPrefix(h.Value, "session=eyJ") {
			weakSignalCount++
			extracted = append(extracted, "Cookie: Flask signed session cookie")
			meta["hasFlaskSession"] = true
			break
		}
	}

	// Weak Signal 4: Response body on error contains "jinja2" or "Jinja2"
	statusCode := ctx.Response().StatusCode()
	if statusCode >= 400 && statusCode < 600 {
		if strings.Contains(body, "jinja2") || strings.Contains(body, "Jinja2") {
			weakSignalCount++
			extracted = append(extracted, "Body: Jinja2 template error")
		}

		// Weak Signal 5: Response body on error contains "Traceback" + "flask" (case insensitive)
		bodyLower := strings.ToLower(body)
		if strings.Contains(bodyLower, "traceback") && strings.Contains(bodyLower, "flask") {
			weakSignalCount++
			extracted = append(extracted, "Body: Flask traceback detected")
		}
	}

	// Require 1+ strong signal or 2+ weak signals
	if !hasStrongSignal && weakSignalCount < 2 {
		return nil, nil
	}

	// Adjust confidence based on signal strength
	confidence := severity.Firm
	if hasStrongSignal {
		confidence = severity.Certain
	}

	desc := "Flask/Werkzeug application detected"
	if _, ok := meta["server"]; ok {
		desc += " (Server: " + meta["server"].(string) + ")"
	}
	if _, ok := meta["hasDebugger"]; ok {
		desc += " with Werkzeug Debugger active"
	}

	if hasStrongSignal {
		scanCtx.MarkTech(host, "flask")
		scanCtx.MarkTech(host, "python")
	}

	return []*output.ResultEvent{
		{
			ModuleID:         ModuleID,
			Host:             host,
			URL:              urlx.String(),
			Matched:          urlx.String(),
			ExtractedResults: extracted,
			Info: output.Info{
				Name:        "Flask/Werkzeug Application Detected",
				Description: desc,
				Severity:    severity.Info,
				Confidence:  confidence,
				Tags:        []string{"python", "flask", "werkzeug", "fingerprint"},
				Reference:   []string{"https://flask.palletsprojects.com/"},
			},
			Metadata: meta,
		},
	}, nil
}
