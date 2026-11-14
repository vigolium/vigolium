package flask_werkzeug_debugger

import (
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/vigolium/vigolium/pkg/utils"
)

type probe struct {
	path        string
	method      string
	body        string
	contentType string
	name        string
}

var debuggerMarkers = []string{
	"Werkzeug Debugger",
	"traceback-repr",
	"debugger.js",
	"console-active",
	"The debugger caught an exception",
	"Traceback (most recent call last)",
}

// Module implements the Flask Werkzeug Debugger active scanner.
type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new Flask Werkzeug Debugger module.
func New() *Module {
	m := &Module{
		BaseActiveModule: modkit.NewBaseActiveModule(
			ModuleID,
			ModuleName,
			ModuleDesc,
			ModuleShort,
			ModuleConfirmation,
			ModuleSeverity,
			ModuleConfidence,
			modkit.ScanScopeRequest,
			modkit.AllInsertionPointTypes,
		),
		ds: dedup.LazyDiskSet("flask_werkzeug_debugger"),
	}
	m.ModuleTags = ModuleTags
	return m
}

func (m *Module) IncludesBaseCanProcess() bool { return false }

func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	if ctx == nil || ctx.Request() == nil {
		return false
	}
	return ctx.Response() != nil
}

// ScanPerRequest probes the host for exposed Werkzeug interactive debugger.
func (m *Module) ScanPerRequest(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	service := ctx.Service()
	if service == nil {
		return nil, nil
	}

	if !modkit.BeginHostProbeFor(scanCtx, httpClient, &m.ds, ctx) {
		return nil, nil
	}

	probes := []probe{
		{
			path:   "/vigolium-werkzeug-test-" + utils.RandomString(8),
			method: "GET",
			name:   "Werkzeug 404 Error",
		},
		{
			path:        "/",
			method:      "POST",
			body:        "{",
			contentType: "application/json",
			name:        "Werkzeug 500 Error",
		},
	}

	var results []*output.ResultEvent
	for _, p := range probes {
		if result := m.probeEndpoint(ctx, httpClient, scanCtx, p); result != nil {
			results = append(results, result)
		}
	}

	return results, nil
}

func (m *Module) probeEndpoint(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
	p probe,
) *output.ResultEvent {
	modifiedRaw, err := httpmsg.SetMethod(ctx.Request().Raw(), p.method)
	if err != nil {
		return nil
	}
	modifiedRaw, err = httpmsg.SetPath(modifiedRaw, p.path)
	if err != nil {
		return nil
	}

	if p.contentType != "" {
		modifiedRaw, err = httpmsg.AddOrReplaceHeader(modifiedRaw, "Content-Type", p.contentType)
		if err != nil {
			return nil
		}
	}
	if p.body != "" {
		modifiedRaw, err = httpmsg.SetBody(modifiedRaw, []byte(p.body))
		if err != nil {
			return nil
		}
	}

	// modifiedRaw is well-formed raw, so wrap directly instead of re-parsing on this hot path.
	fuzzedReq := httpmsg.NewRequestResponseRaw(modifiedRaw, ctx.Service())

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
	if err != nil {
		return nil
	}
	defer resp.Close()

	if resp.Response() == nil {
		return nil
	}

	// Status discipline against the universal catch-all / echo host. A genuine
	// Werkzeug traceback / interactive debugger page is rendered only on an error —
	// a 404 for the random probe path or a 500 from the malformed-JSON probe — so it
	// carries a 4xx/5xx status, NEVER a 2xx. A catch-all / echo host instead answers
	// LITERALLY ANY path with a 200 text/html shell; when a gzip + bogus
	// Content-Length:0 transport quirk truncates the captured body to a tail
	// fragment, a reflected "Traceback (most recent call last)" / "Werkzeug Debugger"
	// token can survive in the tail and forge a finding. The soft-404 body
	// fingerprint below cannot catch a REFLECTING catch-all (distinct head per path),
	// but the surviving HTTP status can — drop any 2xx here.
	if status := resp.Response().StatusCode; status >= 200 && status < 300 {
		return nil
	}

	body := resp.Body().String()

	var matchedMarkers []string
	for _, marker := range debuggerMarkers {
		if strings.Contains(body, marker) {
			matchedMarkers = append(matchedMarkers, marker)
		}
	}
	if len(matchedMarkers) == 0 {
		return nil
	}

	// Strict drop-on-fail: reject a debugger marker that is merely part of the
	// host's catch-all / SPA shell (the same 200 body served for a random path).
	// Real Werkzeug detections come from a 500 error page, whose status differs
	// from the (2xx) wildcard shell, so they are never matched by this gate.
	location := resp.Response().Header.Get("Location")
	if !modkit.ConfirmNotSoft404(scanCtx, httpClient, ctx, resp.Response().StatusCode, []byte(body), location) {
		return nil
	}

	urlx, _ := ctx.URL()
	targetURL := urlx.Scheme + "://" + urlx.Host + p.path

	// Distinguish between full interactive debugger (RCE) and just traceback disclosure
	hasDebugger := strings.Contains(body, "Werkzeug Debugger")

	if hasDebugger {
		return &output.ResultEvent{
			URL:              targetURL,
			Matched:          targetURL,
			Request:          string(modifiedRaw),
			Response:         resp.FullResponseString(),
			ExtractedResults: matchedMarkers,
			Info: output.Info{
				Name:        fmt.Sprintf("Flask Werkzeug Debugger: Interactive Console (%s)", p.name),
				Description: "Werkzeug interactive debugger is exposed, allowing arbitrary Python code execution on the server via the browser console",
				Severity:    severity.Critical,
				Confidence:  severity.Certain,
				Tags:        []string{"python", "flask", "werkzeug", "debugger", "rce"},
				Reference: []string{
					"https://flask.palletsprojects.com/en/latest/debugging/",
					"https://werkzeug.palletsprojects.com/en/latest/debug/",
				},
			},
		}
	}

	return &output.ResultEvent{
		URL:              targetURL,
		Matched:          targetURL,
		Request:          string(modifiedRaw),
		Response:         resp.FullResponseString(),
		ExtractedResults: matchedMarkers,
		Info: output.Info{
			Name:        fmt.Sprintf("Flask Werkzeug Debugger: Stack Trace Disclosure (%s)", p.name),
			Description: "Werkzeug stack trace disclosure detected, exposing internal code paths, file locations, and application structure",
			Severity:    severity.High,
			Confidence:  severity.Firm,
			Tags:        []string{"python", "flask", "werkzeug", "debugger", "rce"},
			Reference: []string{
				"https://flask.palletsprojects.com/en/latest/debugging/",
				"https://werkzeug.palletsprojects.com/en/latest/debug/",
			},
		},
	}
}
