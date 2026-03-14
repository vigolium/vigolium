package subdomain_takeover

import (
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/pkg/errors"
)

// serviceFingerprint defines detection criteria for a deprovisioned cloud service.
type serviceFingerprint struct {
	service     string
	cnames      []string // CNAME patterns that indicate this service
	bodyMarkers []string // strings in response body indicating unclaimed
	statusCode  int      // expected status code (0 = any)
}

var fingerprints = []serviceFingerprint{
	{
		service:     "GitHub Pages",
		cnames:      []string{"github.io"},
		bodyMarkers: []string{"There isn't a GitHub Pages site here.", "For root URLs (like http://example.com/) you must provide an index.html file"},
		statusCode:  404,
	},
	{
		service:     "Heroku",
		cnames:      []string{"herokuapp.com", "herokussl.com", "herokudns.com"},
		bodyMarkers: []string{"No such app", "no-hierarchical-segment", "herokucdn.com/error-pages"},
		statusCode:  404,
	},
	{
		service:     "AWS S3",
		cnames:      []string{"s3.amazonaws.com", ".s3-website"},
		bodyMarkers: []string{"NoSuchBucket", "The specified bucket does not exist"},
		statusCode:  404,
	},
	{
		service:     "Azure",
		cnames:      []string{"azurewebsites.net", "cloudapp.azure.com", "azure-api.net", "azurefd.net", "blob.core.windows.net", "trafficmanager.net"},
		bodyMarkers: []string{"404 Web Site not found", "Azure Web Apps - Web App not found"},
		statusCode:  0,
	},
	{
		service:     "Shopify",
		cnames:      []string{"myshopify.com"},
		bodyMarkers: []string{"Sorry, this shop is currently unavailable", "Only one step left"},
		statusCode:  0,
	},
	{
		service:     "Fastly",
		cnames:      []string{"fastly.net"},
		bodyMarkers: []string{"Fastly error: unknown domain"},
		statusCode:  500,
	},
	{
		service:     "Pantheon",
		cnames:      []string{"pantheonsite.io"},
		bodyMarkers: []string{"404 error unknown site"},
		statusCode:  404,
	},
	{
		service:     "Tumblr",
		cnames:      []string{"domains.tumblr.com"},
		bodyMarkers: []string{"There's nothing here.", "Whatever you were looking for doesn't currently exist at this address"},
		statusCode:  404,
	},
	{
		service:     "WordPress.com",
		cnames:      []string{"wordpress.com"},
		bodyMarkers: []string{"Do you want to register"},
		statusCode:  0,
	},
	{
		service:     "Surge.sh",
		cnames:      []string{"surge.sh"},
		bodyMarkers: []string{"project not found"},
		statusCode:  404,
	},
	{
		service:     "Fly.io",
		cnames:      []string{"fly.dev"},
		bodyMarkers: []string{"404 Not Found"},
		statusCode:  404,
	},
	{
		service:     "Netlify",
		cnames:      []string{"netlify.app", "netlify.com"},
		bodyMarkers: []string{"Not Found - Request ID"},
		statusCode:  404,
	},
}

// Module implements the Subdomain Takeover active scanner.
type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new Subdomain Takeover module.
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
		ds: dedup.LazyDiskSet("subdomain_takeover"),
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

// ScanPerHost checks the host for signs of a deprovisioned cloud service once per host.
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

	// Send GET / to get the default page
	modifiedRaw, err := httpmsg.SetMethod(ctx.Request().Raw(), "GET")
	if err != nil {
		return nil, err
	}
	modifiedRaw, err = httpmsg.SetPath(modifiedRaw, "/")
	if err != nil {
		return nil, err
	}

	fuzzedReq, err := httpmsg.ParseRawRequest(string(modifiedRaw))
	if err != nil {
		return nil, err
	}
	fuzzedReq = fuzzedReq.WithService(ctx.Service())

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{NoRedirects: true})
	if err != nil {
		if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
			return nil, nil
		}
		return nil, err
	}
	defer resp.Close()

	if resp.Response() == nil {
		return nil, nil
	}

	statusCode := resp.Response().StatusCode
	body := resp.Body().String()
	bodyLower := strings.ToLower(body)
	target := ctx.Target()

	for _, fp := range fingerprints {
		if fp.statusCode != 0 && fp.statusCode != statusCode {
			continue
		}

		for _, marker := range fp.bodyMarkers {
			if strings.Contains(bodyLower, strings.ToLower(marker)) {
				return []*output.ResultEvent{
					{
						URL:     target,
						Matched: target,
						Request: string(modifiedRaw),
						Response: truncate(body, 2000),
						ExtractedResults: []string{
							fmt.Sprintf("Service: %s", fp.service),
							fmt.Sprintf("Marker: %s", marker),
							fmt.Sprintf("Host: %s", host),
						},
						Info: output.Info{
							Name:        fmt.Sprintf("Subdomain Takeover: %s", fp.service),
							Description: fmt.Sprintf("The host %s appears to have a dangling DNS record pointing to a deprovisioned %s service. The response contains the fingerprint %q, indicating the service is unclaimed and may be taken over by an attacker.", host, fp.service, marker),
							Severity:    severity.High,
							Confidence:  severity.Firm,
							Tags:        []string{"cloud", "misconfiguration", "subdomain-takeover"},
							Reference:   []string{"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover"},
						},
					},
				}, nil
			}
		}
	}

	return nil, nil
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
