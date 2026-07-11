package subdomain_takeover

import (
	"fmt"
	"net"
	"strings"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// cnameResolver abstracts CNAME resolution so tests can inject a fake (real DNS
// is unavailable and non-deterministic in unit tests).
type cnameResolver interface {
	LookupCNAME(host string) (string, error)
}

// netCNAMEResolver is the default stdlib-backed resolver.
type netCNAMEResolver struct{}

func (netCNAMEResolver) LookupCNAME(host string) (string, error) { return net.LookupCNAME(host) }

// serviceFingerprint defines detection criteria for a deprovisioned cloud service.
type serviceFingerprint struct {
	service     string
	cnames      []string // CNAME patterns that indicate this service
	bodyMarkers []string // strings in response body indicating unclaimed
	statusCode  int      // expected status code (0 = any)
	strong      bool     // provider explicitly describes an unbound resource
}

var fingerprints = []serviceFingerprint{
	{
		service:     "GitHub Pages",
		cnames:      []string{"github.io"},
		bodyMarkers: []string{"There isn't a GitHub Pages site here.", "For root URLs (like http://example.com/) you must provide an index.html file"},
		statusCode:  404,
		strong:      true,
	},
	{
		service:     "Heroku",
		cnames:      []string{"herokuapp.com", "herokussl.com", "herokudns.com"},
		bodyMarkers: []string{"No such app", "no-hierarchical-segment", "herokucdn.com/error-pages"},
		statusCode:  404,
		strong:      true,
	},
	{
		service:     "AWS S3",
		cnames:      []string{"s3.amazonaws.com", ".s3-website"},
		bodyMarkers: []string{"NoSuchBucket", "The specified bucket does not exist"},
		statusCode:  404,
		strong:      true,
	},
	{
		service:     "Azure",
		cnames:      []string{"azurewebsites.net", "cloudapp.azure.com", "azure-api.net", "azurefd.net", "blob.core.windows.net", "trafficmanager.net"},
		bodyMarkers: []string{"404 Web Site not found", "Azure Web Apps - Web App not found"},
		statusCode:  0,
		strong:      true,
	},
	{
		service:     "Shopify",
		cnames:      []string{"myshopify.com"},
		bodyMarkers: []string{"Sorry, this shop is currently unavailable", "Only one step left"},
		statusCode:  0,
		strong:      false,
	},
	{
		service:     "Fastly",
		cnames:      []string{"fastly.net"},
		bodyMarkers: []string{"Fastly error: unknown domain"},
		statusCode:  500,
		strong:      true,
	},
	{
		service:     "Pantheon",
		cnames:      []string{"pantheonsite.io"},
		bodyMarkers: []string{"404 error unknown site"},
		statusCode:  404,
		strong:      true,
	},
	{
		service:     "Tumblr",
		cnames:      []string{"domains.tumblr.com"},
		bodyMarkers: []string{"There's nothing here.", "Whatever you were looking for doesn't currently exist at this address"},
		statusCode:  404,
		strong:      false,
	},
	{
		service:     "WordPress.com",
		cnames:      []string{"wordpress.com"},
		bodyMarkers: []string{"Do you want to register"},
		statusCode:  0,
		strong:      false,
	},
	{
		service:     "Surge.sh",
		cnames:      []string{"surge.sh"},
		bodyMarkers: []string{"project not found"},
		statusCode:  404,
		strong:      true,
	},
	{
		service:     "Fly.io",
		cnames:      []string{"fly.dev"},
		bodyMarkers: []string{"404 Not Found"},
		statusCode:  404,
		strong:      false,
	},
	{
		service:     "Netlify",
		cnames:      []string{"netlify.app", "netlify.com"},
		bodyMarkers: []string{"Not Found - Request ID"},
		statusCode:  404,
		strong:      true,
	},
}

type takeoverCapture struct {
	status   int
	body     string
	request  string
	response string
}

// Module implements the Subdomain Takeover active scanner.
type Module struct {
	modkit.BaseActiveModule
	ds       dedup.Lazy[dedup.DiskSet]
	resolver cnameResolver
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
		ds:       dedup.LazyDiskSet("subdomain_takeover"),
		resolver: netCNAMEResolver{},
	}
	m.ModuleTags = ModuleTags
	return m
}

// cnamePointsToService resolves the host's CNAME and reports whether it points at
// one of the service's CNAME patterns. conclusive is false on a DNS lookup error;
// callers retain only an observation in that case, never a takeover candidate.
func (m *Module) cnamePointsToService(host string, servicePatterns []string) (matches, conclusive bool) {
	r := m.resolver
	if r == nil {
		r = netCNAMEResolver{}
	}
	// Strip any :port — DNS lookups take a bare hostname.
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	cname, err := r.LookupCNAME(host)
	if err != nil {
		return false, false // inconclusive (NXDOMAIN / transient)
	}
	c := strings.TrimSuffix(strings.ToLower(cname), ".")
	for _, p := range servicePatterns {
		if cnameMatchesPattern(c, p) {
			return true, true
		}
	}
	return false, true // resolved a canonical name that is not this service
}

func cnameMatchesPattern(cname, pattern string) bool {
	cname = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(cname)), ".")
	pattern = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(pattern)), ".")
	if pattern == ".s3-website" {
		return strings.Contains(cname, ".s3-website") && strings.HasSuffix(cname, ".amazonaws.com")
	}
	pattern = strings.TrimPrefix(pattern, ".")
	return cname == pattern || strings.HasSuffix(cname, "."+pattern)
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
	if scanCtx != nil {
		diskSet := m.ds.Get(scanCtx.DedupMgr())
		if diskSet != nil && diskSet.IsSeen(host) {
			return nil, nil
		}
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

	modifiedRaw, err = stripCredentials(modifiedRaw)
	if err != nil {
		return nil, err
	}
	anonymousClient, err := httpClient.CloneWithoutCredentials()
	if err != nil {
		return nil, nil
	}
	first, err := m.fetch(ctx, anonymousClient, modifiedRaw)
	if err != nil {
		if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
			return nil, nil
		}
		return nil, err
	}
	bodyLower := strings.ToLower(first.body)
	target := ctx.Target()

	for _, fp := range fingerprints {
		if fp.statusCode != 0 && fp.statusCode != first.status {
			continue
		}

		for _, marker := range fp.bodyMarkers {
			if strings.Contains(bodyLower, strings.ToLower(marker)) {
				second, replayErr := m.fetch(ctx, anonymousClient, modifiedRaw)
				if replayErr != nil || (fp.statusCode != 0 && fp.statusCode != second.status) || !strings.Contains(strings.ToLower(second.body), strings.ToLower(marker)) {
					continue
				}
				matches, conclusive := m.cnamePointsToService(host, fp.cnames)
				if conclusive && !matches {
					continue
				}

				kind := output.RecordKindObservation
				grade := output.EvidenceGradeObservation
				sev := severity.Info
				name := fmt.Sprintf("Deprovisioned Service Fingerprint Observed: %s", fp.service)
				description := fmt.Sprintf("The host %s reproducibly returned the %s deprovisioned-service fingerprint, but DNS provider binding was inconclusive. This is an observation, not takeover proof.", host, fp.service)
				if matches && fp.strong {
					kind = output.RecordKindCandidate
					grade = output.EvidenceGradeDifferential
					sev = ModuleSeverity
					name = fmt.Sprintf("Dangling Subdomain Candidate: %s", fp.service)
					description = fmt.Sprintf("The host %s has a CNAME bound to %s and reproducibly returns its explicit unclaimed-resource fingerprint %q. This is a strong dangling-service candidate, but actual namespace claimability was not tested.", host, fp.service, marker)
				} else if matches {
					description = fmt.Sprintf("The host %s has a CNAME bound to %s and reproducibly returns %q, but that response can also describe an unavailable or ordinary missing site. Claimability was not demonstrated.", host, fp.service, marker)
				}
				return []*output.ResultEvent{
					{
						ModuleID:      ModuleID,
						RecordKind:    kind,
						EvidenceGrade: grade,
						URL:           target,
						Matched:       target,
						Request:       first.request,
						Response:      first.response,
						AdditionalEvidence: []string{
							output.BuildEvidence("credential-free fingerprint replay", second.request, second.response),
						},
						ExtractedResults: []string{
							fmt.Sprintf("Service: %s", fp.service),
							fmt.Sprintf("Marker: %s", marker),
							fmt.Sprintf("Host: %s", host),
						},
						Info: output.Info{
							Name:        name,
							Description: description,
							Severity:    sev,
							Confidence:  ModuleConfidence,
							Tags:        ModuleTags,
							Reference:   []string{"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover"},
						},
						Metadata: map[string]any{
							"service":               fp.service,
							"cname_confirmed":       matches,
							"dns_conclusive":        conclusive,
							"strong_fingerprint":    fp.strong,
							"confirmation_rounds":   2,
							"claimability_tested":   false,
							"resource_registration": false,
						},
					},
				}, nil
			}
		}
	}

	return nil, nil
}

func (m *Module) fetch(ctx *httpmsg.HttpRequestResponse, client *http.Requester, raw []byte) (takeoverCapture, error) {
	req := httpmsg.NewRequestResponseRaw(raw, ctx.Service())
	resp, _, err := client.Execute(req, http.Options{NoRedirects: true, NoClustering: true})
	if err != nil {
		return takeoverCapture{}, err
	}
	defer resp.Close()
	if resp.Response() == nil || infra.IsBlockedResponse(resp) {
		return takeoverCapture{}, nil
	}
	return takeoverCapture{
		status:   resp.Response().StatusCode,
		body:     resp.BodyString(),
		request:  string(raw),
		response: resp.FullResponseString(),
	}, nil
}

func stripCredentials(raw []byte) ([]byte, error) {
	clean := append([]byte(nil), raw...)
	var err error
	for _, name := range []string{"Authorization", "Proxy-Authorization", "Cookie", "X-API-Key", "Api-Key", "X-Auth-Token", "X-Access-Token"} {
		clean, err = httpmsg.RemoveHeader(clean, name)
		if err != nil {
			return nil, err
		}
	}
	return clean, nil
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
