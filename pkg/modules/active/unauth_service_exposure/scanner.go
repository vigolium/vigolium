package unauth_service_exposure

import (
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// Structural signatures. Each is unique to its service — a JSON key/value shape or
// a fixed banner string a generic web host, SPA shell, or catch-all 404 never
// carries — so the signature match is itself the false-positive guard.
var (
	reK8sAPIVersions = regexp.MustCompile(`"kind"\s*:\s*"APIVersions"`)
	rePodList        = regexp.MustCompile(`"kind"\s*:\s*"PodList"`)
	reCouchWelcome   = regexp.MustCompile(`"couchdb"\s*:\s*"Welcome"`)
)

// serviceProbe describes one unauthenticated-service check: the paths to try
// (first structural hit wins), the confirmation predicate, and how to report it.
type serviceProbe struct {
	name     string
	paths    []string
	severity severity.Severity
	summary  string
	confirm  func(status int, header func(string) string, body string) bool
}

// probes is the catalog. Signatures are intentionally strict (multiple JSON keys
// or a unique banner) so only the genuine service matches.
var probes = []serviceProbe{
	{
		name:     "Docker Engine API",
		paths:    []string{"/version", "/v1.41/version", "/info"},
		severity: severity.Critical,
		summary:  "The Docker Engine remote API is reachable without authentication — equivalent to root on the host (an attacker can start a privileged container mounting the host filesystem).",
		confirm: func(status int, _ func(string) string, body string) bool {
			return status == 200 && strings.Contains(body, "ApiVersion") &&
				(strings.Contains(body, "KernelVersion") || strings.Contains(body, "GoVersion") || strings.Contains(body, "Containers"))
		},
	},
	{
		name:     "Docker Registry v2",
		paths:    []string{"/v2/", "/v2/_catalog"},
		severity: severity.High,
		summary:  "A Docker Registry v2 API is reachable without authentication, exposing (and potentially allowing modification of) hosted images and their layers.",
		confirm: func(status int, header func(string) string, body string) bool {
			if status != 200 {
				return false
			}
			return strings.Contains(strings.ToLower(header("Docker-Distribution-Api-Version")), "registry") ||
				strings.Contains(body, "repositories")
		},
	},
	{
		name:     "Kubernetes API server",
		paths:    []string{"/version", "/api"},
		severity: severity.High,
		summary:  "The Kubernetes API server answers anonymously, disclosing version/API surface and — if anonymous-auth is enabled — cluster resources.",
		confirm: func(status int, _ func(string) string, body string) bool {
			if status != 200 {
				return false
			}
			if reK8sAPIVersions.MatchString(body) {
				return true
			}
			return strings.Contains(body, "gitVersion") && strings.Contains(body, "goVersion") && strings.Contains(body, "compiler")
		},
	},
	{
		name:     "Kubelet API",
		paths:    []string{"/pods", "/runningpods/"},
		severity: severity.Critical,
		summary:  "The kubelet read/exec API is reachable anonymously, listing running pods and enabling command execution inside workloads.",
		confirm: func(status int, _ func(string) string, body string) bool {
			return status == 200 && rePodList.MatchString(body)
		},
	},
	{
		name:     "Elasticsearch",
		paths:    []string{"/", "/_cat/indices?format=json", "/_cluster/health"},
		severity: severity.High,
		summary:  "An Elasticsearch node answers unauthenticated, exposing (and allowing dump/modify of) all indexed data.",
		confirm: func(status int, _ func(string) string, body string) bool {
			if status != 200 {
				return false
			}
			// The root banner tagline is unique to Elasticsearch.
			if strings.Contains(body, "You Know, for Search") && strings.Contains(body, "cluster_name") {
				return true
			}
			// _cat/indices JSON rows carry a health/status/index shape.
			return strings.Contains(body, "\"health\"") && strings.Contains(body, "\"index\"") && strings.Contains(body, "\"docs.count\"")
		},
	},
	{
		name:     "Apache CouchDB",
		paths:    []string{"/", "/_all_dbs"},
		severity: severity.High,
		summary:  "A CouchDB instance answers unauthenticated, exposing databases and allowing read/write of all documents.",
		confirm: func(status int, _ func(string) string, body string) bool {
			return status == 200 && reCouchWelcome.MatchString(body)
		},
	},
	{
		name:     "Apache Solr",
		paths:    []string{"/solr/admin/info/system?wt=json", "/solr/admin/cores?wt=json"},
		severity: severity.Medium,
		summary:  "A Solr admin API answers unauthenticated, exposing cores/config and (with known CVEs) enabling data access or RCE.",
		confirm: func(status int, _ func(string) string, body string) bool {
			if status != 200 {
				return false
			}
			return strings.Contains(body, "responseHeader") && (strings.Contains(body, "lucene") || strings.Contains(body, "solr_home"))
		},
	},
}

// Module implements the Unauthenticated Infrastructure Service Exposure scanner.
type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new module instance.
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
		ds: dedup.LazyDiskSet("unauth_service_exposure"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// IncludesBaseCanProcess returns false because this module uses a custom CanProcess.
func (m *Module) IncludesBaseCanProcess() bool { return false }

// CanProcess accepts any request carrying a resolvable service.
func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	return ctx != nil && ctx.Request() != nil && ctx.Service() != nil
}

// ScanPerHost probes the target host:port for each unauthenticated infrastructure
// service and reports the first one whose unique structural signature confirms
// (re-verified with a second request). Only the scanned host:port is probed — no
// speculative port scanning.
func (m *Module) ScanPerHost(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	svc := ctx.Service()
	if svc == nil {
		return nil, nil
	}
	base := baseURL(svc)
	if base == "" {
		return nil, nil
	}

	diskSet := m.ds.Get(scanCtx.DedupMgr())
	if diskSet != nil && diskSet.IsSeen(base) {
		return nil, nil
	}

	for _, p := range probes {
		for _, path := range p.paths {
			body, header, status, ok := m.fetch(httpClient, base+path)
			if !ok || !p.confirm(status, header, body) {
				continue
			}
			// Multi-round confirmation: a second independent request must reproduce
			// the signature, so a one-off/proxied artifact can't create a finding.
			body2, header2, status2, ok2 := m.fetch(httpClient, base+path)
			if !ok2 || !p.confirm(status2, header2, body2) {
				continue
			}
			return []*output.ResultEvent{m.result(base, path, p, body)}, nil
		}
	}
	return nil, nil
}

// fetch issues a GET and returns the body, a header accessor, the status, and
// whether the request succeeded and was not a WAF/CDN block.
func (m *Module) fetch(httpClient *http.Requester, url string) (body string, header func(string) string, status int, ok bool) {
	rr, err := httpmsg.GetRawRequestFromURL(url)
	if err != nil {
		return "", nil, 0, false
	}
	resp, _, err := httpClient.Execute(rr, http.Options{})
	if err != nil {
		return "", nil, 0, false
	}
	defer resp.Close()
	if infra.IsBlockedResponse(resp) {
		return "", nil, 0, false
	}
	r := resp.Response()
	if r == nil {
		return "", nil, 0, false
	}
	return resp.Body().String(), r.Header.Get, r.StatusCode, true
}

// result builds the finding for a confirmed service exposure.
func (m *Module) result(base, path string, p serviceProbe, body string) *output.ResultEvent {
	target := base + path
	evidence := body
	if len(evidence) > 600 {
		evidence = evidence[:600]
	}
	return &output.ResultEvent{
		ModuleID: ModuleID,
		URL:      target,
		Matched:  target,
		ExtractedResults: []string{
			"service=" + p.name,
			"endpoint=" + target,
			"evidence=" + strings.TrimSpace(evidence),
		},
		Info: output.Info{
			Name:        "Unauthenticated " + p.name + " Exposed",
			Description: p.summary + " Confirmed by the service's unique unauthenticated API response at " + path + " (re-verified with a second request).",
			Severity:    p.severity,
			Confidence:  ModuleConfidence,
			Tags:        append(append([]string{}, ModuleTags...), strings.ToLower(strings.ReplaceAll(p.name, " ", "-"))),
		},
	}
}

// baseURL renders scheme://host[:port] for the service, omitting the port when it
// is the scheme default.
func baseURL(svc *httpmsg.Service) string {
	scheme := strings.ToLower(svc.Protocol())
	host := svc.Host()
	if host == "" {
		return ""
	}
	port := svc.Port()
	if port == 0 || isDefaultPort(scheme, port) {
		return scheme + "://" + host
	}
	return scheme + "://" + net.JoinHostPort(host, strconv.Itoa(port))
}

func isDefaultPort(scheme string, port int) bool {
	return (scheme == "http" && port == 80) || (scheme == "https" && port == 443)
}
