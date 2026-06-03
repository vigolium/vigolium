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
type probe struct {
	path        string
	framework   string
	description string
	match       func(statusCode int, body string) bool
}

var probes = []probe{
	// Remix
	{"/__remix_manifest", "Remix", "Remix manifest file exposed", func(sc int, body string) bool {
		return sc == 200 && strings.Contains(body, "routes")
	}},
	{"/__remix/dev", "Remix", "Remix dev server endpoint exposed", func(sc int, body string) bool {
		return sc == 200 && (strings.Contains(body, "remix") || strings.Contains(body, "dev") || strings.Contains(body, "hmr"))
	}},

	// Astro
	{"/_astro/", "Astro", "Astro build directory listing", func(sc int, body string) bool {
		return sc == 200 && (strings.Contains(body, "Index of") || strings.Contains(body, ".astro"))
	}},
	{"/.astro/", "Astro", "Astro internal directory exposed", func(sc int, body string) bool {
		return sc == 200 && (strings.Contains(body, "Index of") || strings.Contains(body, ".astro") || strings.Contains(body, "astro"))
	}},
	{"/__astro_dev_toolbar/", "Astro", "Astro dev toolbar exposed in production", func(sc int, body string) bool {
		return sc == 200 && (strings.Contains(body, "astro") || strings.Contains(body, "toolbar") || strings.Contains(body, "dev-toolbar"))
	}},

	// SvelteKit
	{"/_app/version.json", "SvelteKit", "SvelteKit version file exposed", func(sc int, body string) bool {
		return sc == 200 && strings.Contains(body, "version")
	}},
	{"/.svelte-kit/", "SvelteKit", "SvelteKit build directory exposed", func(sc int, body string) bool {
		return sc == 200 && (strings.Contains(body, "Index of") || strings.Contains(body, "output"))
	}},
	{"/__data.json", "SvelteKit", "SvelteKit data endpoint exposed", func(sc int, body string) bool {
		return sc == 200 && (strings.Contains(body, "type") || strings.Contains(body, "nodes"))
	}},
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

		if resp.Response() != nil {
			body := resp.FullResponseString()
			if p.match(resp.Response().StatusCode, body) {
				results = append(results, &output.ResultEvent{
					URL:      target,
					Matched:  target,
					Request:  string(modifiedRaw),
					Response: body,
					ExtractedResults: []string{
						fmt.Sprintf("Framework: %s", p.framework),
						fmt.Sprintf("Path: %s", p.path),
						fmt.Sprintf("Status: %d", resp.Response().StatusCode),
					},
					Info: output.Info{
						Name:        fmt.Sprintf("%s - %s", p.framework, p.description),
						Description: fmt.Sprintf("The %s framework endpoint at %s is accessible in production. %s.", p.framework, p.path, p.description),
					},
				})
			}
		}
		resp.Close()
	}

	return results, nil
}
