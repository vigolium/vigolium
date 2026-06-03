package cloud_public_read

import (
	"fmt"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

const minBodyLength = 50

type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

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
		ds: dedup.LazyDiskSet("cloud_public_read"),
	}
	m.ModuleTags = ModuleTags
	return m
}

func (m *Module) IncludesBaseCanProcess() bool { return false }

func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	if ctx == nil || ctx.Request() == nil || ctx.Response() == nil {
		return false
	}
	if ctx.Service() == nil {
		return false
	}
	return isCloudStorageHost(ctx.Service().Host())
}

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
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	if diskSet != nil && diskSet.IsSeen(host) {
		return nil, nil
	}

	var results []*output.ResultEvent

	for _, sp := range sensitivePaths {
		result, err := m.probePath(ctx, httpClient, scanCtx, sp.path, sp.desc)
		if err != nil {
			continue
		}
		if result != nil {
			results = append(results, result)
		}
	}

	return results, nil
}

func (m *Module) probePath(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
	path string,
	desc string,
) (*output.ResultEvent, error) {
	modifiedRaw, err := httpmsg.SetMethod(ctx.Request().Raw(), "GET")
	if err != nil {
		return nil, err
	}
	modifiedRaw, err = httpmsg.SetPath(modifiedRaw, path)
	if err != nil {
		return nil, err
	}

	fuzzedReq, err := httpmsg.ParseRawRequest(string(modifiedRaw))
	if err != nil {
		return nil, err
	}
	fuzzedReq = fuzzedReq.WithService(ctx.Service())

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
	if err != nil {
		return nil, err
	}
	defer resp.Close()

	if resp.Response() == nil {
		return nil, nil
	}

	statusCode := resp.Response().StatusCode
	if statusCode != 200 && statusCode != 206 {
		return nil, nil
	}

	body := resp.Body().String()

	// Verify real content
	if len(body) < minBodyLength {
		return nil, nil
	}
	if isErrorResponse(body) {
		return nil, nil
	}

	// Reject hosts that return a 2xx shell for ANY path (SPA / wildcard /
	// catch-all CDN) and redirects to a login page — otherwise every sensitive
	// path "exists". WildcardProbe fingerprints a random path on the host and
	// ConfirmNotSoft404 fails open on a probe error so a real exposure is never
	// suppressed by a transient failure.
	location := resp.Response().Header.Get("Location")
	if !modkit.ConfirmNotSoft404(scanCtx, httpClient, ctx, statusCode, []byte(body), location) {
		return nil, nil
	}

	target := ctx.Target()
	host := ""
	if ctx.Service() != nil {
		host = ctx.Service().Host()
	}

	// Each finding gets its own collector. The original crawl-time pair for this
	// cloud-storage host is the baseline the public-read probe was issued against;
	// attaching it as supporting context shows what the host returned before the
	// sensitive-path access. The wildcard/soft-404 probe lives inside the shared
	// ConfirmNotSoft404 helper and is not exposed at this emit site, so it cannot
	// be captured here without modifying shared code.
	ev := modkit.NewEvidenceCollector()
	if origReq := ctx.Request(); origReq != nil {
		var origRespStr string
		if origResp := ctx.Response(); origResp != nil {
			origRespStr = string(origResp.Raw())
		}
		ev.Add("baseline", string(origReq.Raw()), origRespStr)
	}

	return &output.ResultEvent{
		URL:                target,
		Matched:            target,
		Request:            string(modifiedRaw),
		Response:           truncate(body, 2000),
		AdditionalEvidence: ev.Entries(),
		ExtractedResults: []string{
			fmt.Sprintf("Path: %s", path),
			fmt.Sprintf("Description: %s", desc),
			fmt.Sprintf("Status: %d", statusCode),
			fmt.Sprintf("Body length: %d", len(body)),
		},
		Info: output.Info{
			Name:        fmt.Sprintf("Cloud Public Read: %s", desc),
			Description: fmt.Sprintf("Cloud storage endpoint %s exposes %s at path %s without authentication (%d bytes)", host, desc, path, len(body)),
			Severity:    severity.High,
			Confidence:  severity.Firm,
			Tags:        []string{"cloud-storage", "public-read", "data-exposure"},
			Reference:   []string{"https://owasp.org/www-project-web-security-testing-guide/"},
		},
	}, nil
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
