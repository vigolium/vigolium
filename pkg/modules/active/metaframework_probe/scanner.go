package metaframework_probe

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

// probe defines a framework-specific path to test and its match criteria.
//
// The matcher receives the probe's status code, response Content-Type, and the
// response BODY (not the full raw response). Matchers must demand framework
// artifact-specific content — never a bare generic substring — because the most
// common deployment for these targets is a single-page-app whose reverse proxy
// returns the same 200 text/html shell for every path. A lazy substring like
// "dev" matches "device-width" in a viewport meta tag and a lazy "version" /
// "type" / "nodes" matches arbitrary JSON, so every matcher below either
// rejects the HTML shell outright or requires an autoindex directory listing.
type probe struct {
	path        string
	framework   string
	description string
	match       func(statusCode int, contentType, body string) bool
}

var probes = []probe{
	// Remix — the manifest is a JS/JSON document describing routes and the
	// entry bundle. It is never the app's HTML shell, so require both quoted
	// JSON keys and reject anything that looks like HTML.
	{"/__remix_manifest", "Remix", "Remix manifest file exposed", func(sc int, ct, body string) bool {
		return sc == 200 && !isHTMLShell(ct, body) &&
			strings.Contains(body, `"routes"`) &&
			(strings.Contains(body, `"entry"`) || strings.Contains(body, `"assets"`))
	}},
	// Remix dev/HMR endpoint — emits a remix-specific dev payload (JSON or an
	// event stream), never the application HTML shell. Require the literal
	// "remix" token plus a dev/HMR signal so a catch-all 200 cannot match on
	// "dev" alone (which otherwise hits "device-width").
	{"/__remix/dev", "Remix", "Remix dev server endpoint exposed", func(sc int, ct, body string) bool {
		if sc != 200 || isHTMLShell(ct, body) {
			return false
		}
		low := strings.ToLower(body)
		return strings.Contains(low, "remix") &&
			(strings.Contains(low, "hmr") ||
				strings.Contains(low, "livereload") ||
				strings.Contains(low, "live-reload") ||
				strings.Contains(low, `"version"`))
	}},

	// Astro — the build/internal directories only confirm via a real autoindex
	// listing whose title carries the probed path. An SPA shell has no
	// "Index of /" marker.
	{"/_astro/", "Astro", "Astro build directory listing", func(sc int, ct, body string) bool {
		return sc == 200 && isDirListing(body) && strings.Contains(strings.ToLower(body), "_astro")
	}},
	{"/.astro/", "Astro", "Astro internal directory exposed", func(sc int, ct, body string) bool {
		return sc == 200 && isDirListing(body) && strings.Contains(strings.ToLower(body), ".astro")
	}},
	{"/__astro_dev_toolbar/", "Astro", "Astro dev toolbar exposed in production", func(sc int, ct, body string) bool {
		if sc != 200 {
			return false
		}
		low := strings.ToLower(body)
		// Either an autoindex of the toolbar dir, or the toolbar's own JS asset
		// — but never the plain HTML application shell.
		if isDirListing(body) && strings.Contains(low, "astro") {
			return true
		}
		return !isHTMLShell(ct, body) && strings.Contains(low, "astro") && strings.Contains(low, "toolbar")
	}},

	// SvelteKit — version.json is a tiny JSON document {"version":"<ts>"}. Demand
	// JSON content (not the HTML shell) carrying the "version" key.
	{"/_app/version.json", "SvelteKit", "SvelteKit version file exposed", func(sc int, ct, body string) bool {
		return sc == 200 && isJSON(ct, body) && strings.Contains(body, `"version"`)
	}},
	{"/.svelte-kit/", "SvelteKit", "SvelteKit build directory exposed", func(sc int, ct, body string) bool {
		return sc == 200 && isDirListing(body) && strings.Contains(strings.ToLower(body), "svelte-kit")
	}},
	// SvelteKit data endpoint returns {"type":"data","nodes":[...]} (devalue).
	// Require JSON plus both structural keys so generic JSON cannot match.
	{"/__data.json", "SvelteKit", "SvelteKit data endpoint exposed", func(sc int, ct, body string) bool {
		return sc == 200 && isJSON(ct, body) &&
			strings.Contains(body, `"type"`) && strings.Contains(body, `"nodes"`)
	}},
}

// isHTMLShell reports whether the response looks like an HTML document — the
// hallmark of a single-page-app catch-all that serves index.html for every
// path. Framework manifest/data/version artifacts are JSON or JS, never HTML.
func isHTMLShell(contentType, body string) bool {
	if strings.Contains(strings.ToLower(contentType), "text/html") {
		return true
	}
	// Some catch-all proxies drop the Content-Type; sniff the body too.
	head := strings.ToLower(strings.TrimSpace(body))
	return strings.HasPrefix(head, "<!doctype html") || strings.HasPrefix(head, "<html")
}

// isJSON reports whether the response is JSON, by Content-Type or by a leading
// brace/bracket when the proxy omits the header.
func isJSON(contentType, body string) bool {
	ct := strings.ToLower(contentType)
	if strings.Contains(ct, "application/json") || strings.Contains(ct, "+json") {
		return true
	}
	if isHTMLShell(contentType, body) {
		return false
	}
	head := strings.TrimSpace(body)
	return strings.HasPrefix(head, "{") || strings.HasPrefix(head, "[")
}

// isDirListing reports whether the body is a server-generated directory
// (autoindex) listing — the "Index of /" marker emitted by Apache/nginx/Caddy.
func isDirListing(body string) bool {
	low := strings.ToLower(body)
	return strings.Contains(low, "index of /") || strings.Contains(low, "<title>directory listing")
}

// Module implements the Metaframework Probe active scanner.
type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new Metaframework Probe module.
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
		ds: dedup.LazyDiskSet("metaframework_probe"),
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

// ScanPerHost probes for exposed meta-framework files and endpoints once per host.
func (m *Module) ScanPerHost(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	service := ctx.Service()
	if service == nil {
		return nil, nil
	}

	host := service.Host()

	// Dedup by host
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	if diskSet != nil && diskSet.IsSeen(host) {
		return nil, nil
	}

	// Probe the host once with a random nonexistent path. If it answers with a
	// 2xx shell, it's a single-page-app / wildcard reverse proxy that returns
	// the same body for every URL — so a 200 on any framework path proves
	// nothing and must be rejected below.
	wildcard, _ := scanCtx.WildcardProbe(ctx, httpClient)

	var results []*output.ResultEvent
	target := ctx.Target()

	for _, p := range probes {
		modifiedRaw, err := httpmsg.SetPath(ctx.Request().Raw(), p.path)
		if err != nil {
			continue
		}

		fuzzedReq, err := httpmsg.ParseRawRequest(string(modifiedRaw))
		if err != nil {
			continue
		}
		fuzzedReq = fuzzedReq.WithService(ctx.Service())

		resp, _, err := httpClient.Execute(fuzzedReq, http.Options{NoRedirects: true})
		if err != nil {
			if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
				return results, nil
			}
			continue
		}

		httpResp := resp.Response()
		if httpResp == nil {
			resp.Close()
			continue
		}

		statusCode := httpResp.StatusCode
		bodyBytes := resp.BodyBytes()

		// Reject the catch-all / SPA wildcard shell before matching: if this
		// probe path returns the same body the host serves for a random
		// nonexistent path, it is not an exposed framework artifact.
		if wildcard.MatchesBody(statusCode, bodyBytes) {
			resp.Close()
			continue
		}

		contentType := httpResp.Header.Get("Content-Type")
		body := string(bodyBytes)

		if p.match(statusCode, contentType, body) {
			results = append(results, &output.ResultEvent{
				URL:      target,
				Matched:  target,
				Request:  string(modifiedRaw),
				Response: resp.FullResponseString(),
				ExtractedResults: []string{
					fmt.Sprintf("Framework: %s", p.framework),
					fmt.Sprintf("Path: %s", p.path),
					fmt.Sprintf("Status: %d", statusCode),
					fmt.Sprintf("Content-Type: %s", contentType),
				},
				Info: output.Info{
					Name:        fmt.Sprintf("%s - %s", p.framework, p.description),
					Description: fmt.Sprintf("The %s framework endpoint at %s is accessible in production. %s.", p.framework, p.path, p.description),
				},
			})
		}
		resp.Close()
	}

	return results, nil
}
