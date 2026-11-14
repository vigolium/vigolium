package iis_cookieless_source_disclosure

import (
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/iisgate"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/utils"
)

// maxRequestsPerHost bounds probe cost per host.
const maxRequestsPerHost = 160

// Module discloses protected ASP.NET config/source files via ASP.NET cookieless
// (S(X)) path-confusion, confirmation-gated to avoid false positives.
type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new IIS Cookieless Source/Config Disclosure module.
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
		ds: dedup.LazyDiskSet("iis_cookieless_source_disclosure"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// IncludesBaseCanProcess returns false to use custom CanProcess logic.
func (m *Module) IncludesBaseCanProcess() bool { return false }

// CanProcess is a fast pre-filter; ScanPerHost applies stronger IIS gating.
func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	if ctx == nil || ctx.Request() == nil || ctx.Response() == nil {
		return false
	}
	return iisgate.RespLooksIIS(ctx.Response())
}

// ScanPerHost probes named protected files behind cookieless bypass vectors.
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

	// Gate: passive detection AND active behavioral confirmation (a spoofed
	// Server header alone never passes). Cached per host across IIS modules.
	if !iisgate.IsIIS(ctx, scanCtx, host, httpClient) {
		return nil, nil
	}

	diskSet := m.ds.Get(scanCtx.DedupMgr())
	if !modkit.BeginHostProbe(scanCtx, httpClient, diskSet, host) {
		return nil, nil
	}

	urlx, err := ctx.URL()
	if err != nil {
		return nil, nil
	}
	baseURL := urlx.Scheme + "://" + urlx.Host

	budget := 0
	var results []*output.ResultEvent
	for _, t := range targets {
		if budget >= maxRequestsPerHost {
			break
		}
		if r := m.probeTarget(ctx, httpClient, &budget, baseURL, t); r != nil {
			results = append(results, r)
		}
	}
	return results, nil
}

// probeTarget attempts direct download and, if blocked, each cookieless vector,
// confirming through independent rounds before reporting.
func (m *Module) probeTarget(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	budget *int,
	baseURL string,
	t target,
) *output.ResultEvent {
	// Round 0: direct request. If the file is already served, that is itself a
	// disclosure (no bypass needed).
	if body, ok := m.get(ctx, httpClient, budget, "/"+t.rel); ok {
		if confirmed, ev := confirmArtifact(t.kind, body); confirmed && !modkit.ResemblesObservedPage(ctx, body) {
			return buildFinding(baseURL, t, "/"+t.rel, "direct request (no bypass required)", ev, body)
		}
	}

	for shape := 0; shape < numVectorShapes; shape++ {
		if *budget >= maxRequestsPerHost {
			break
		}
		token := strings.ToLower(utils.RandomString(6))
		path, ok := buildVector(t.rel, shape, token)
		if !ok {
			continue
		}

		// Round 1: bypass attempt must return the real artifact.
		body, ok := m.get(ctx, httpClient, budget, path)
		if !ok {
			continue
		}
		confirmed, ev := confirmArtifact(t.kind, body)
		if !confirmed || modkit.ResemblesObservedPage(ctx, body) {
			continue
		}

		// Round 2: decoy negative — the same vector shape on a random non-existent
		// file must NOT return artifact-like content (rules out a catch-all that
		// echoes config for any path).
		decoyRel := "vigolium-" + strings.ToLower(utils.RandomString(10)) + extOfRel(t.rel)
		if decoyPath, dok := buildVector(decoyRel, shape, token); dok {
			if decoyBody, dok2 := m.get(ctx, httpClient, budget, decoyPath); dok2 {
				if dConfirmed, _ := confirmArtifact(t.kind, decoyBody); dConfirmed {
					return nil // catch-all: abandon this target entirely
				}
			}
		}

		// Round 3: re-confirm determinism.
		again, ok := m.get(ctx, httpClient, budget, path)
		if !ok {
			continue
		}
		if reConfirmed, _ := confirmArtifact(t.kind, again); !reConfirmed {
			continue
		}

		return buildFinding(baseURL, t, path, fmt.Sprintf("cookieless (S(X)) bypass shape #%d", shape), ev, body)
	}

	return nil
}

// get sends a GET probe and returns a capped body snapshot, incrementing budget.
// NoClustering keeps each round (including the Round-3 determinism re-fetch) off
// the requester's short-lived response cache.
func (m *Module) get(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	budget *int,
	path string,
) (string, bool) {
	*budget++

	raw, err := httpmsg.SetMethod(ctx.Request().Raw(), "GET")
	if err != nil {
		return "", false
	}
	raw, err = httpmsg.SetPath(raw, path)
	if err != nil {
		return "", false
	}

	_, body, ok := modkit.ExecuteRaw(httpClient, ctx.Service(), raw, http.Options{NoRedirects: true, NoClustering: true})
	if !ok {
		return "", false
	}
	if len(body) > 8192 {
		body = body[:8192]
	}
	return body, true
}

// buildFinding assembles a High-severity disclosure finding.
func buildFinding(baseURL string, t target, path, method string, evidence []string, body string) *output.ResultEvent {
	fullURL := baseURL + path
	snippet := body
	if len(snippet) > 400 {
		snippet = snippet[:400]
	}

	desc := fmt.Sprintf(
		"The protected file **%s** was disclosed via %s.\n\n"+
			"**URL:** `%s`\n\n"+
			"**Evidence markers:** %s\n\n"+
			"**Response snippet:**\n```\n%s\n```\n\n"+
			"web.config and related files hold machine keys (enabling ViewState forgery / RCE via ysoserial.net), "+
			"connection strings, and other secrets. Source files leak application logic.",
		t.name, method, fullURL, strings.Join(evidence, ", "), snippet,
	)

	return &output.ResultEvent{
		ModuleID:         ModuleID,
		URL:              fullURL,
		Matched:          fullURL,
		ExtractedResults: evidence,
		Info: output.Info{
			Name:        fmt.Sprintf("IIS Protected File Disclosure: %s", t.name),
			Description: desc,
			Severity:    ModuleSeverity,
			Confidence:  ModuleConfidence,
			Tags:        []string{"iis", "aspnet", "info-disclosure", "cookieless"},
			Reference: []string{
				"https://soroush.secproject.com/downloadable/microsoft_iis_tilde_character_vulnerability_feature.pdf",
				"https://mll.sh/humiliating-iis-servers-for-fun-and-jail-time/",
			},
		},
	}
}
