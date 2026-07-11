package unauth_service_exposure

import (
	"encoding/json"
	"net"
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

// A service fingerprint proves reachability, not compromise. Each endpoint
// assessor therefore assigns the narrowest supported confidence tier:
//
//   - observation: a native service/version response was reproduced;
//   - candidate: an administrative collection or operational metadata was read;
//   - finding: real workload/container/document data was returned anonymously.
//
// No mutating request is sent by this module.
type probeAssessment struct {
	kind          output.RecordKind
	grade         output.EvidenceGrade
	severity      severity.Severity
	claim         string
	proof         string
	resourceCount int
}

type endpointProbe struct {
	path   string
	assess func(status int, header func(string) string, body string) (probeAssessment, bool)
}

type serviceProbe struct {
	name      string
	endpoints []endpointProbe
}

var probes = []serviceProbe{
	{
		name: "Docker Engine API",
		endpoints: []endpointProbe{
			{path: "/containers/json?all=1", assess: assessDockerContainers},
			{path: "/info", assess: assessDockerInfo},
			{path: "/version", assess: assessDockerVersion},
			{path: "/v1.41/version", assess: assessDockerVersion},
		},
	},
	{
		name: "Docker Registry v2",
		endpoints: []endpointProbe{
			{path: "/v2/_catalog", assess: assessRegistryCatalog},
			{path: "/v2/", assess: assessRegistryRoot},
		},
	},
	{
		name: "Kubernetes API server",
		endpoints: []endpointProbe{
			{path: "/api/v1/pods?limit=1", assess: assessKubernetesList("PodList", "pod")},
			{path: "/api/v1/namespaces?limit=1", assess: assessKubernetesList("NamespaceList", "namespace")},
			{path: "/api", assess: assessKubernetesAPIVersions},
			{path: "/version", assess: assessKubernetesVersion},
		},
	},
	{
		name: "Kubelet API",
		endpoints: []endpointProbe{
			{path: "/pods", assess: assessKubernetesList("PodList", "pod")},
			{path: "/runningpods/", assess: assessKubernetesList("PodList", "pod")},
		},
	},
	{
		name: "Elasticsearch",
		endpoints: []endpointProbe{
			{path: "/_search?size=1&track_total_hits=false", assess: assessElasticsearchSearch},
			{path: "/_cat/indices?format=json&h=health,status,index,docs.count", assess: assessElasticsearchIndices},
			{path: "/_cluster/health", assess: assessElasticsearchHealth},
			{path: "/", assess: assessElasticsearchRoot},
		},
	},
	{
		name: "Apache CouchDB",
		endpoints: []endpointProbe{
			{path: "/_all_dbs", assess: assessCouchDBs},
			{path: "/", assess: assessCouchRoot},
		},
	},
	{
		name: "Apache Solr",
		endpoints: []endpointProbe{
			{path: "/solr/admin/cores?wt=json", assess: assessSolrCores},
			{path: "/solr/admin/info/system?wt=json", assess: assessSolrSystem},
		},
	},
}

type probeResponse struct {
	body     string
	header   func(string) string
	status   int
	request  string
	response string
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

// ScanPerHost probes only the already-scanned host:port. Every request is a safe
// GET made with an isolated credential-free client. A match must reproduce in a
// second network request at the same evidence tier.
func (m *Module) ScanPerHost(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	if ctx == nil || ctx.Service() == nil || httpClient == nil {
		return nil, nil
	}
	base := baseURL(ctx.Service())
	if base == "" {
		return nil, nil
	}

	diskSet := m.ds.Get(scanCtx.DedupMgr())
	if diskSet != nil && diskSet.IsSeen(base) {
		return nil, nil
	}

	anonymousClient, err := httpClient.CloneWithoutCredentials()
	if err != nil {
		return nil, nil
	}

	for _, service := range probes {
		for _, endpoint := range service.endpoints {
			first, ok := m.fetch(anonymousClient, base+endpoint.path)
			if !ok || servedAsHTML(first.header) {
				continue
			}
			firstAssessment, matched := endpoint.assess(first.status, first.header, first.body)
			if !matched {
				continue
			}

			second, ok := m.fetch(anonymousClient, base+endpoint.path)
			if !ok || servedAsHTML(second.header) {
				continue
			}
			secondAssessment, reproduced := endpoint.assess(second.status, second.header, second.body)
			if !reproduced || firstAssessment.kind != secondAssessment.kind || firstAssessment.grade != secondAssessment.grade {
				continue
			}

			return []*output.ResultEvent{m.result(ctx.Service().Host(), base, service, endpoint, firstAssessment, first, second)}, nil
		}
	}
	return nil, nil
}

func servedAsHTML(header func(string) string) bool {
	if header == nil {
		return false
	}
	return modkit.ClassifyContentType(header("Content-Type")) == modkit.ContentClassHTML
}

// fetch disables clustering so the confirmation request cannot be satisfied by
// the request cache, and redirects so a login or generic landing page cannot be
// mistaken for the management API.
func (m *Module) fetch(httpClient *http.Requester, url string) (probeResponse, bool) {
	rr, err := httpmsg.GetRawRequestFromURL(url)
	if err != nil || rr == nil || rr.Request() == nil {
		return probeResponse{}, false
	}
	resp, _, err := httpClient.Execute(rr, http.Options{NoClustering: true, NoRedirects: true})
	if err != nil {
		return probeResponse{}, false
	}
	defer resp.Close()
	if infra.IsBlockedResponse(resp) || resp.Response() == nil {
		return probeResponse{}, false
	}
	r := resp.Response()
	return probeResponse{
		body:     resp.Body().String(),
		header:   r.Header.Get,
		status:   r.StatusCode,
		request:  string(rr.Request().Raw()),
		response: resp.FullResponseString(),
	}, true
}

func (m *Module) result(host, base string, service serviceProbe, endpoint endpointProbe, assessment probeAssessment, first, second probeResponse) *output.ResultEvent {
	target := base + endpoint.path
	evidence := strings.TrimSpace(first.body)
	if len(evidence) > 600 {
		evidence = evidence[:600]
	}

	namePrefix := "Observed"
	switch assessment.kind {
	case output.RecordKindCandidate:
		namePrefix = "Candidate"
	case output.RecordKindFinding:
		namePrefix = "Confirmed"
	}

	return &output.ResultEvent{
		ModuleID:      ModuleID,
		RecordKind:    assessment.kind,
		EvidenceGrade: assessment.grade,
		Host:          host,
		URL:           target,
		Matched:       target,
		Request:       first.request,
		Response:      first.response,
		AdditionalEvidence: []string{
			output.BuildEvidence("credential-free confirmation", second.request, second.response),
		},
		ExtractedResults: []string{
			"service=" + service.name,
			"endpoint=" + target,
			"proof=" + assessment.proof,
			"evidence=" + evidence,
		},
		Info: output.Info{
			Name:        namePrefix + " Unauthenticated " + service.name + " Exposure",
			Description: assessment.claim + " The native response was reproduced by a second request from an isolated credential-free client. No write, command-execution, or privilege-escalation capability is inferred unless it was directly demonstrated.",
			Severity:    assessment.severity,
			Confidence:  ModuleConfidence,
			Tags:        append(append([]string{}, ModuleTags...), strings.ToLower(strings.ReplaceAll(service.name, " ", "-"))),
		},
		Metadata: map[string]any{
			"anonymous_client":    true,
			"confirmation_rounds": 2,
			"safe_read_only":      true,
			"resource_count":      assessment.resourceCount,
			"proof":               assessment.proof,
		},
	}
}

func observation(claim, proof string) probeAssessment {
	return probeAssessment{
		kind:     output.RecordKindObservation,
		grade:    output.EvidenceGradeObservation,
		severity: severity.Info,
		claim:    claim,
		proof:    proof,
	}
}

func candidate(sev severity.Severity, count int, claim, proof string) probeAssessment {
	return probeAssessment{
		kind:          output.RecordKindCandidate,
		grade:         output.EvidenceGradeDifferential,
		severity:      sev,
		claim:         claim,
		proof:         proof,
		resourceCount: count,
	}
}

func finding(sev severity.Severity, count int, claim, proof string) probeAssessment {
	return probeAssessment{
		kind:          output.RecordKindFinding,
		grade:         output.EvidenceGradeImpact,
		severity:      sev,
		claim:         claim,
		proof:         proof,
		resourceCount: count,
	}
}

func assessDockerContainers(status int, _ func(string) string, body string) (probeAssessment, bool) {
	if status != 200 {
		return probeAssessment{}, false
	}
	var rows []struct {
		ID    string   `json:"Id"`
		Image string   `json:"Image"`
		Names []string `json:"Names"`
	}
	if json.Unmarshal([]byte(body), &rows) != nil || len(rows) == 0 {
		return probeAssessment{}, false
	}
	valid := 0
	for _, row := range rows {
		if row.ID != "" && (row.Image != "" || len(row.Names) > 0) {
			valid++
		}
	}
	if valid == 0 {
		return probeAssessment{}, false
	}
	return finding(severity.High, valid, "The Docker API returned real container inventory without credentials, confirming anonymous read access to workload metadata.", "container-inventory"), true
}

func assessDockerInfo(status int, _ func(string) string, body string) (probeAssessment, bool) {
	if status != 200 {
		return probeAssessment{}, false
	}
	var value map[string]json.RawMessage
	if json.Unmarshal([]byte(body), &value) != nil {
		return probeAssessment{}, false
	}
	_, hasContainers := value["Containers"]
	_, hasImages := value["Images"]
	_, hasDriver := value["Driver"]
	_, hasServerVersion := value["ServerVersion"]
	if !hasContainers || !hasImages || (!hasDriver && !hasServerVersion) {
		return probeAssessment{}, false
	}
	return candidate(severity.Medium, 0, "The Docker API returned daemon operational metadata without credentials. This does not by itself prove container creation, host-root access, or another mutating capability.", "daemon-info"), true
}

func assessDockerVersion(status int, _ func(string) string, body string) (probeAssessment, bool) {
	if status != 200 {
		return probeAssessment{}, false
	}
	var value map[string]json.RawMessage
	if json.Unmarshal([]byte(body), &value) != nil {
		return probeAssessment{}, false
	}
	if !jsonStringPresent(value, "ApiVersion") || (!jsonStringPresent(value, "KernelVersion") && !jsonStringPresent(value, "GoVersion")) {
		return probeAssessment{}, false
	}
	return observation("A Docker Engine version endpoint is reachable without credentials. Version reachability alone does not prove access to privileged daemon operations.", "native-version-response"), true
}

func assessRegistryCatalog(status int, header func(string) string, body string) (probeAssessment, bool) {
	if status != 200 {
		return probeAssessment{}, false
	}
	var value map[string]json.RawMessage
	if json.Unmarshal([]byte(body), &value) != nil {
		return probeAssessment{}, false
	}
	raw, exists := value["repositories"]
	if !exists {
		return probeAssessment{}, false
	}
	var repositories []string
	if json.Unmarshal(raw, &repositories) != nil {
		return probeAssessment{}, false
	}
	if len(repositories) == 0 {
		return observation("A Docker Registry catalog endpoint answered without credentials, but it returned no repository names.", "empty-registry-catalog"), true
	}
	return candidate(severity.Medium, len(repositories), "The Docker Registry returned repository names without credentials. Public registries may intentionally expose this metadata; image contents or write access were not demonstrated.", "repository-catalog"), true
}

func assessRegistryRoot(status int, header func(string) string, _ string) (probeAssessment, bool) {
	if status != 200 || header == nil || !strings.Contains(strings.ToLower(header("Docker-Distribution-Api-Version")), "registry") {
		return probeAssessment{}, false
	}
	return observation("A Docker Registry v2 service header is reachable without credentials. The header alone establishes service presence, not repository read or write access.", "native-service-header"), true
}

func assessKubernetesList(kind, resource string) func(int, func(string) string, string) (probeAssessment, bool) {
	return func(status int, _ func(string) string, body string) (probeAssessment, bool) {
		if status != 200 {
			return probeAssessment{}, false
		}
		var value struct {
			Kind       string            `json:"kind"`
			APIVersion string            `json:"apiVersion"`
			Items      []json.RawMessage `json:"items"`
		}
		if json.Unmarshal([]byte(body), &value) != nil || value.Kind != kind || value.APIVersion == "" || value.Items == nil {
			return probeAssessment{}, false
		}
		if len(value.Items) == 0 {
			return candidate(severity.Medium, 0, "The Kubernetes endpoint accepted an anonymous "+resource+" listing request but returned an empty collection. Dangerous permissions were not demonstrated.", "empty-"+resource+"-list"), true
		}
		return finding(severity.High, len(value.Items), "The Kubernetes endpoint returned real "+resource+" objects without credentials, confirming anonymous read access to cluster/workload metadata.", resource+"-objects"), true
	}
}

func assessKubernetesAPIVersions(status int, _ func(string) string, body string) (probeAssessment, bool) {
	if status != 200 {
		return probeAssessment{}, false
	}
	var value struct {
		Kind     string   `json:"kind"`
		Versions []string `json:"versions"`
	}
	if json.Unmarshal([]byte(body), &value) != nil || value.Kind != "APIVersions" || len(value.Versions) == 0 {
		return probeAssessment{}, false
	}
	return observation("The Kubernetes API discovery endpoint is anonymously reachable. API discovery alone does not prove access to cluster resources.", "api-discovery"), true
}

func assessKubernetesVersion(status int, _ func(string) string, body string) (probeAssessment, bool) {
	if status != 200 {
		return probeAssessment{}, false
	}
	var value map[string]json.RawMessage
	if json.Unmarshal([]byte(body), &value) != nil || !jsonStringPresent(value, "gitVersion") || !jsonStringPresent(value, "goVersion") || !jsonStringPresent(value, "compiler") {
		return probeAssessment{}, false
	}
	return observation("A Kubernetes version endpoint is anonymously reachable. Version disclosure alone does not establish access to cluster resources.", "native-version-response"), true
}

func assessElasticsearchSearch(status int, _ func(string) string, body string) (probeAssessment, bool) {
	if status != 200 {
		return probeAssessment{}, false
	}
	var value struct {
		Took   json.RawMessage `json:"took"`
		Shards json.RawMessage `json:"_shards"`
		Hits   struct {
			Hits []map[string]json.RawMessage `json:"hits"`
		} `json:"hits"`
	}
	if json.Unmarshal([]byte(body), &value) != nil || len(value.Took) == 0 || len(value.Shards) == 0 || len(value.Hits.Hits) == 0 {
		return probeAssessment{}, false
	}
	withSource := 0
	for _, hit := range value.Hits.Hits {
		if source, ok := hit["_source"]; ok && len(source) > 0 && string(source) != "null" && string(source) != "{}" {
			withSource++
		}
	}
	if withSource == 0 {
		return probeAssessment{}, false
	}
	return finding(severity.High, withSource, "Elasticsearch returned stored document content without credentials, confirming anonymous data read access.", "document-content"), true
}

func assessElasticsearchIndices(status int, header func(string) string, body string) (probeAssessment, bool) {
	if status != 200 {
		return probeAssessment{}, false
	}
	var rows []map[string]json.RawMessage
	if json.Unmarshal([]byte(body), &rows) != nil {
		return probeAssessment{}, false
	}
	valid := 0
	for _, row := range rows {
		if jsonStringPresent(row, "index") && (jsonStringPresent(row, "health") || jsonStringPresent(row, "status") || jsonStringPresent(row, "docs.count")) {
			valid++
		}
	}
	if valid == 0 {
		if len(rows) == 0 && header != nil && strings.EqualFold(strings.TrimSpace(header("X-Elastic-Product")), "Elasticsearch") {
			return observation("The Elasticsearch indices API answered anonymously but returned no index metadata.", "empty-index-list"), true
		}
		return probeAssessment{}, false
	}
	return candidate(severity.Medium, valid, "Elasticsearch returned index names and statistics without credentials. This is meaningful metadata exposure, but document content and write access were not demonstrated.", "index-metadata"), true
}

func assessElasticsearchHealth(status int, _ func(string) string, body string) (probeAssessment, bool) {
	if status != 200 {
		return probeAssessment{}, false
	}
	var value map[string]json.RawMessage
	if json.Unmarshal([]byte(body), &value) != nil || !jsonStringPresent(value, "cluster_name") {
		return probeAssessment{}, false
	}
	var state string
	if json.Unmarshal(value["status"], &state) != nil || (state != "green" && state != "yellow" && state != "red") {
		return probeAssessment{}, false
	}
	return candidate(severity.Low, 0, "Elasticsearch returned live cluster-health metadata without credentials. Index contents and write access were not demonstrated.", "cluster-health"), true
}

func assessElasticsearchRoot(status int, _ func(string) string, body string) (probeAssessment, bool) {
	if status != 200 {
		return probeAssessment{}, false
	}
	var value struct {
		ClusterName string `json:"cluster_name"`
		Tagline     string `json:"tagline"`
	}
	if json.Unmarshal([]byte(body), &value) != nil || value.ClusterName == "" || value.Tagline != "You Know, for Search" {
		return probeAssessment{}, false
	}
	return observation("An Elasticsearch root banner is anonymously reachable. A banner does not establish index, document, or write access.", "native-root-banner"), true
}

func assessCouchDBs(status int, header func(string) string, body string) (probeAssessment, bool) {
	if status != 200 || header == nil || !strings.Contains(strings.ToLower(header("Server")), "couchdb") {
		return probeAssessment{}, false
	}
	var databases []string
	if json.Unmarshal([]byte(body), &databases) != nil {
		return probeAssessment{}, false
	}
	if len(databases) == 0 {
		return observation("The CouchDB database-list endpoint answered without credentials but returned no database names.", "empty-database-list"), true
	}
	return candidate(severity.Medium, len(databases), "CouchDB returned database names without credentials. Database names are useful exposure evidence, but document contents and write access were not demonstrated.", "database-names"), true
}

func assessCouchRoot(status int, _ func(string) string, body string) (probeAssessment, bool) {
	if status != 200 {
		return probeAssessment{}, false
	}
	var value struct {
		CouchDB string `json:"couchdb"`
		UUID    string `json:"uuid"`
		Vendor  any    `json:"vendor"`
	}
	if json.Unmarshal([]byte(body), &value) != nil || value.CouchDB != "Welcome" || (value.UUID == "" && value.Vendor == nil) {
		return probeAssessment{}, false
	}
	return observation("A native CouchDB welcome response is anonymously reachable. The banner does not prove database read or write access.", "native-root-banner"), true
}

func assessSolrCores(status int, _ func(string) string, body string) (probeAssessment, bool) {
	if status != 200 {
		return probeAssessment{}, false
	}
	var value struct {
		ResponseHeader map[string]json.RawMessage            `json:"responseHeader"`
		Status         map[string]map[string]json.RawMessage `json:"status"`
		InitFailures   map[string]json.RawMessage            `json:"initFailures"`
	}
	if json.Unmarshal([]byte(body), &value) != nil || value.ResponseHeader == nil || value.Status == nil {
		return probeAssessment{}, false
	}
	if len(value.Status) == 0 {
		return observation("The Solr core-admin endpoint answered without credentials but returned no core metadata.", "empty-core-list"), true
	}
	return candidate(severity.Medium, len(value.Status), "Solr returned core names and administrative metadata without credentials. Stored documents, configuration changes, and code execution were not demonstrated.", "core-metadata"), true
}

func assessSolrSystem(status int, _ func(string) string, body string) (probeAssessment, bool) {
	if status != 200 {
		return probeAssessment{}, false
	}
	var value map[string]json.RawMessage
	if json.Unmarshal([]byte(body), &value) != nil {
		return probeAssessment{}, false
	}
	_, responseHeader := value["responseHeader"]
	_, lucene := value["lucene"]
	_, solrHome := value["solr_home"]
	if !responseHeader || (!lucene && !solrHome) {
		return probeAssessment{}, false
	}
	return observation("A Solr system-information endpoint is anonymously reachable. System metadata alone does not prove document access, configuration changes, or code execution.", "system-information"), true
}

func jsonStringPresent(value map[string]json.RawMessage, key string) bool {
	raw, ok := value[key]
	if !ok {
		return false
	}
	var text string
	return json.Unmarshal(raw, &text) == nil && strings.TrimSpace(text) != ""
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
