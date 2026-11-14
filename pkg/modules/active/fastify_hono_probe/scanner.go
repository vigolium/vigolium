package fastify_hono_probe

import (
	"fmt"
	"strings"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
)

// probe defines a framework-specific path to test and its match criteria. The
// matcher receives the status code, the response Content-Type, and the decoded
// body so it can demand resource-specific content rather than trusting a bare
// 2xx — the latter is meaningless against an SPA/CDN catch-all that answers
// every path with a 200 shell (the motivating false positive: a CloudFront/SPA
// gateway returned `200 OK`, `text/html`, empty body for /.well-known/fastify/
// metrics and every other probe).
type probe struct {
	path        string
	framework   string
	description string
	match       func(statusCode int, contentType, body string) bool
}

var probes = []probe{
	// Fastify
	{"/documentation/json", "Fastify", "Fastify Swagger documentation exposed", func(sc int, ct, body string) bool {
		// The OpenAPI/Swagger spec is served as JSON; an HTML shell is the SPA
		// fallback, not the spec.
		return sc == 200 && !isHTMLContentType(ct) && (strings.Contains(body, "swagger") || strings.Contains(body, "openapi"))
	}},
	{"/documentation/", "Fastify", "Fastify Swagger UI exposed", func(sc int, ct, body string) bool {
		return sc == 200 && strings.Contains(body, "swagger")
	}},
	{"/documentation/static/index.html", "Fastify", "Fastify Swagger static UI exposed", func(sc int, ct, body string) bool {
		return sc == 200 && strings.Contains(body, "swagger")
	}},
	{"/.well-known/fastify/metrics", "Fastify", "Fastify metrics endpoint exposed", func(sc int, ct, body string) bool {
		// A metrics endpoint returns Prometheus exposition text or a JSON runtime
		// snapshot — never an HTML page. Requiring recognizable metrics content
		// (not just a 200) is what separates a real exposed endpoint from a
		// catch-all shell.
		return sc == 200 && !isHTMLContentType(ct) && looksLikeMetrics(body)
	}},
	{"/fastify-overview", "Fastify", "Fastify overview plugin exposed", func(sc int, ct, body string) bool {
		return sc == 200 && strings.Contains(body, "fastify")
	}},

	// Hono
	{"/doc", "Hono", "Hono API documentation exposed", func(sc int, ct, body string) bool {
		return sc == 200 && !isHTMLContentType(ct) && (strings.Contains(body, "openapi") || strings.Contains(body, "swagger"))
	}},
	{"/ui", "Hono", "Hono Swagger UI exposed", func(sc int, ct, body string) bool {
		return sc == 200 && strings.Contains(body, "swagger")
	}},
	{"/reference", "Hono", "Hono API reference exposed", func(sc int, ct, body string) bool {
		return sc == 200 && (strings.Contains(body, "scalar") || strings.Contains(body, "openapi"))
	}},
}

// isHTMLContentType reports whether the Content-Type is an HTML document — the
// hallmark of an SPA/CDN catch-all shell. The JSON/metrics probes use this to
// reject a fallback page that merely happens to return 200.
func isHTMLContentType(contentType string) bool {
	return strings.Contains(strings.ToLower(contentType), "text/html")
}

// looksLikeMetrics reports whether body carries recognizable runtime-metrics
// content: Prometheus exposition markers (every Prometheus endpoint emits
// `# HELP`/`# TYPE` comment lines and process_/nodejs_ metric families) or the
// JSON keys a Node/Fastify metrics snapshot exposes. A blank or HTML body — the
// catch-all signature — matches none of these.
func looksLikeMetrics(body string) bool {
	if strings.Contains(body, "# HELP ") || strings.Contains(body, "# TYPE ") {
		return true
	}
	for _, marker := range []string{
		"process_cpu_", "process_resident_memory", "nodejs_",
		"eventLoopUtilization", "eventLoopDelay", "heapUsed", "heapTotal",
	} {
		if strings.Contains(body, marker) {
			return true
		}
	}
	return false
}

// Module implements the Fastify/Hono Probe active scanner.
type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new Fastify/Hono Probe module.
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
			modkit.ScanScopeHost,
			modkit.AllInsertionPointTypes,
		),
		ds: dedup.LazyDiskSet("fastify_hono_probe"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// IncludesBaseCanProcess returns false because this module uses a custom CanProcess.
func (m *Module) IncludesBaseCanProcess() bool { return false }

// CanProcess returns true if the request has a response.
func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	return ctx != nil && ctx.Request() != nil && ctx.Response() != nil
}

// ScanPerHost probes for exposed Fastify and Hono endpoints once per host.
func (m *Module) ScanPerHost(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	service := ctx.Service()
	if service == nil {
		return nil, nil
	}

	// Dedup by host
	if !modkit.BeginHostProbeFor(scanCtx, httpClient, &m.ds, ctx) {
		return nil, nil
	}

	var results []*output.ResultEvent
	target := ctx.Target()

	for _, p := range probes {
		modifiedRaw, err := httpmsg.SetPath(ctx.Request().Raw(), p.path)
		if err != nil {
			continue
		}

		// modifiedRaw is well-formed raw, so wrap directly instead of re-parsing on this hot path.
		fuzzedReq := httpmsg.NewRequestResponseRaw(modifiedRaw, ctx.Service())

		resp, _, err := httpClient.Execute(fuzzedReq, http.Options{NoRedirects: true})
		if err != nil {
			if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
				return results, nil
			}
			continue
		}

		if resp.Response() != nil {
			statusCode := resp.Response().StatusCode
			contentType := resp.Response().Header.Get("Content-Type")
			respBody := resp.Body().String()

			// Self-reflection / echo-server guard: a catch-all or echo handler that
			// mirrors the requested path into its response body lets a probe whose
			// content marker is a substring of its OWN path self-confirm — the
			// /fastify-overview probe (marker "fastify") sees the word reflected
			// straight back from "/fastify-overview" and forges an "overview plugin
			// exposed" finding. Strip the reflected probe path before matching so a
			// marker only counts when it comes from the endpoint's real content, not
			// our own request. This survives the gzip + bogus `Content-Length: 0`
			// truncation that drops the shell head but keeps the reflected tail — the
			// case the head-keyed ConfirmNotSoft404 wildcard guard below cannot see.
			// The original respBody is kept for the empty-body gate and evidence.
			matchBody := modkit.StripReflectedProbePath(respBody, p.path)

			// An exposed documentation / metrics / debug endpoint always returns a
			// non-empty, resource-specific body. A blank 200 is the signature of an
			// SPA/CDN catch-all that answers every path with an empty shell, so it
			// can never be a genuine hit — skip it before the per-probe match.
			if strings.TrimSpace(respBody) != "" && p.match(statusCode, contentType, matchBody) {
				location := resp.Response().Header.Get("Location")
				// Defense-in-depth for catch-alls whose shell is non-empty: reject the
				// match when it is indistinguishable from the host's wildcard response
				// to a random path (cached per host, fails open on probe error so a
				// real endpoint is never suppressed by a flaky probe).
				if modkit.ConfirmNotSoft404(scanCtx, httpClient, ctx, statusCode, []byte(respBody), location) {
					results = append(results, &output.ResultEvent{
						URL:      target,
						Matched:  target,
						Request:  string(modifiedRaw),
						Response: resp.FullResponseString(),
						ExtractedResults: []string{
							fmt.Sprintf("Framework: %s", p.framework),
							fmt.Sprintf("Path: %s", p.path),
							fmt.Sprintf("Status: %d", statusCode),
						},
						Info: output.Info{
							Name:        fmt.Sprintf("%s - %s", p.framework, p.description),
							Description: fmt.Sprintf("The %s framework endpoint at %s is accessible in production. %s.", p.framework, p.path, p.description),
						},
					})
				}
			}
		}
		resp.Close()
	}

	return results, nil
}
