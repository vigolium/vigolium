package cloud_storage_listing

import (
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

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
		ds: dedup.LazyDiskSet("cloud_storage_listing"),
	}
	m.ModuleTags = ModuleTags
	return m
}

func (m *Module) IncludesBaseCanProcess() bool { return false }

func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	if ctx == nil || ctx.Request() == nil || ctx.Response() == nil {
		return false
	}
	host := ""
	if ctx.Service() != nil {
		host = ctx.Service().Host()
	}
	if host == "" {
		return false
	}
	isS3, isAzure := isCloudStorageHost(host)
	return isS3 || isAzure
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
	if !modkit.BeginHostProbeFor(scanCtx, httpClient, &m.ds, ctx) {
		return nil, nil
	}

	isS3, isAzure := isCloudStorageHost(host)

	var results []*output.ResultEvent

	if isS3 {
		for _, probe := range s3ListingProbes {
			result, err := m.tryProbe(ctx, httpClient, probe)
			if err != nil {
				continue
			}
			if result != nil {
				results = append(results, result)
			}
		}
	}

	if isAzure {
		// Try account-level container listing
		for _, probe := range azureListingProbes {
			result, err := m.tryProbe(ctx, httpClient, probe)
			if err != nil {
				continue
			}
			if result != nil {
				results = append(results, result)
			}
		}

		// Try container-level blob listing if we can derive the container name
		urlx, err := ctx.URL()
		if err == nil {
			container := getAzureContainerFromPath(urlx.Path)
			if container != "" {
				containerProbe := listingProbe{
					name:    "Azure Container Blob List",
					path:    fmt.Sprintf("/%s?restype=container&comp=list", container),
					markers: []string{"<Blobs>", "<Blob>", "<Name>"},
				}
				result, err := m.tryProbe(ctx, httpClient, containerProbe)
				if err == nil && result != nil {
					results = append(results, result)
				}
			}
		}
	}

	return results, nil
}

func (m *Module) tryProbe(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	probe listingProbe,
) (*output.ResultEvent, error) {
	modifiedRaw, err := httpmsg.SetMethod(ctx.Request().Raw(), "GET")
	if err != nil {
		return nil, err
	}
	modifiedRaw, err = httpmsg.SetPath(modifiedRaw, probe.path)
	if err != nil {
		return nil, err
	}

	// SetMethod/SetPath produce well-formed raw, so wrap directly instead
	// of re-parsing on this hot path.
	fuzzedReq := httpmsg.NewRequestResponseRaw(modifiedRaw, ctx.Service())

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
	if err != nil {
		return nil, err
	}
	defer resp.Close()

	if resp.Response() == nil || resp.Response().StatusCode != 200 {
		return nil, nil
	}

	// Content-type discipline: a genuine S3/Azure bucket listing is an XML
	// document (application/xml). A universal catch-all / static-website host that
	// answers every path with a 200 text/html shell — or the gzip/Content-Length:0
	// transport quirk that captures only a reflecting tail fragment of one — can
	// carry a stray "<Key>"/"<Name>"/"<Container>" and forge a listing. Reject an
	// HTML document: the XML listing markers only count in a non-HTML response.
	if servedAsHTMLDoc(resp.Response().Header.Get("Content-Type")) {
		return nil, nil
	}

	body := resp.Body().String()
	if !bodyContainsAll(body, probe.markers) {
		return nil, nil
	}

	// Count items for evidence
	itemCount := strings.Count(body, "<Key>") + strings.Count(body, "<Name>")

	target := ctx.Target()

	return &output.ResultEvent{
		URL:      target,
		Matched:  target,
		Request:  string(modifiedRaw),
		Response: modkit.Truncate(body, 2000),
		ExtractedResults: []string{
			fmt.Sprintf("Probe: %s", probe.name),
			fmt.Sprintf("Items found: %d", itemCount),
		},
		Info: output.Info{
			Name:        fmt.Sprintf("Public Storage Listing: %s", probe.name),
			Description: fmt.Sprintf("Cloud storage endpoint allows public listing via %s, exposing %d item(s)", probe.name, itemCount),
			Severity:    severity.High,
			Confidence:  severity.Certain,
			Tags:        []string{"cloud-storage", "listing", "misconfiguration"},
			Reference:   []string{"https://owasp.org/www-project-web-security-testing-guide/"},
		},
	}, nil
}
