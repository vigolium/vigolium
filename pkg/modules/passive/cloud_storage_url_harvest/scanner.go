package cloud_storage_url_harvest

import (
	"fmt"
	"net/url"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/storagesig"
)

const (
	// maxBody caps how large a response body we scan for storage URLs.
	maxBody = 2 << 20 // 2 MB
	// maxCandidates caps storage URLs harvested per response.
	maxCandidates = 50
)

type Module struct {
	modkit.BasePassiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

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
		ds: dedup.LazyDiskSet("passive_cloud_storage_url_harvest"),
	}
	m.ModuleTags = ModuleTags
	return m
}

func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	if ctx == nil || ctx.Response() == nil {
		return nil, nil
	}
	// Only mine text bodies — never binary/asset bodies (those are the objects,
	// not the pages that reference them).
	if modkit.IsStaticAssetContentType(ctx.Response().Header("Content-Type")) {
		return nil, nil
	}
	body := ctx.Response().BodyToString()
	if len(body) == 0 || len(body) > maxBody {
		return nil, nil
	}

	candidates := storagesig.ExtractStorageURLs(body, maxCandidates)
	if len(candidates) == 0 {
		return nil, nil
	}

	ds := m.ds.Get(scanCtx.DedupMgr())
	feeder := scanCtx.Feeder()

	var harvested []string
	fed := 0
	for _, c := range candidates {
		key := storagesig.HostBucketKey(c)
		if key == "" {
			continue
		}
		if ds != nil && ds.IsSeen(key) {
			continue // bucket already harvested this scan
		}
		harvested = append(harvested, c)
		if feeder != nil {
			if rr := buildGetRequest(c); rr != nil && feeder.Feed(rr) {
				fed++
			}
		}
	}

	if len(harvested) == 0 {
		return nil, nil
	}

	source := ""
	if u, err := ctx.URL(); err == nil {
		source = u.String()
	}

	return []*output.ResultEvent{{
		ModuleID:         ModuleID,
		Host:             hostOf(ctx),
		URL:              source,
		Matched:          source,
		ExtractedResults: harvested,
		Info: output.Info{
			Name: "Cloud Storage Object URLs Harvested",
			Description: fmt.Sprintf(
				"Discovered %d object-storage object URL(s) referenced in this response and queued %d new bucket(s) for active traversal probing. "+
					"These are tracked without storing their (often binary) object bodies.",
				len(harvested), fed,
			),
			Severity:   ModuleSeverity,
			Confidence: ModuleConfidence,
			Tags:       ModuleTags,
		},
	}}, nil
}

// buildGetRequest constructs a pipeline-injectable GET request for an absolute
// object-storage URL, with its Service derived from the URL.
func buildGetRequest(absURL string) *httpmsg.HttpRequestResponse {
	u, err := url.Parse(absURL)
	if err != nil || u.Host == "" {
		return nil
	}
	reqURI := u.RequestURI()
	if reqURI == "" {
		reqURI = "/"
	}
	raw := "GET " + reqURI + " HTTP/1.1\r\nHost: " + u.Host + "\r\n\r\n"
	rr, err := httpmsg.ParseRawRequestWithURL(raw, absURL)
	if err != nil {
		return nil
	}
	return rr
}

func hostOf(ctx *httpmsg.HttpRequestResponse) string {
	if ctx.Service() != nil {
		return ctx.Service().Host()
	}
	return ""
}

// BodyOnly opts into once-per-distinct-body dispatch (modules.BodyOnlyPassive):
// the verdict is a function of the response body, so an identical body served
// at another URL is not re-analysed (ECON-14).
func (m *Module) BodyOnly() bool { return true }
