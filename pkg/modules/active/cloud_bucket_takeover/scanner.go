package cloud_bucket_takeover

import (
	"fmt"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

type cloudCapture struct {
	status   int
	body     string
	request  string
	response string
}

type Module struct {
	modkit.BaseActiveModule
	ds                 dedup.Lazy[dedup.DiskSet]
	providerClassifier func(string) string
}

func New() *Module {
	m := &Module{
		BaseActiveModule: modkit.NewBaseActiveModule(
			ModuleID, ModuleName, ModuleDesc, ModuleShort, ModuleConfirmation,
			ModuleSeverity, ModuleConfidence,
			modkit.ScanScopeHost, modkit.AllInsertionPointTypes,
		),
		ds:                 dedup.LazyDiskSet("cloud_bucket_takeover"),
		providerClassifier: cloudProviderForHost,
	}
	m.ModuleTags = ModuleTags
	return m
}

func (m *Module) IncludesBaseCanProcess() bool { return false }

func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	return ctx != nil && ctx.Request() != nil && ctx.Response() != nil && ctx.Service() != nil && isCloudStorageHost(ctx.Service().Host())
}

func (m *Module) ScanPerHost(ctx *httpmsg.HttpRequestResponse, httpClient *http.Requester, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	if ctx == nil || ctx.Request() == nil || ctx.Service() == nil || httpClient == nil {
		return nil, nil
	}
	host := ctx.Service().Host()
	classifier := m.providerClassifier
	if classifier == nil {
		classifier = cloudProviderForHost
	}
	provider := classifier(host)
	if provider == "" {
		return nil, nil
	}
	if scanCtx != nil {
		diskSet := m.ds.Get(scanCtx.DedupMgr())
		if diskSet != nil && diskSet.IsSeen(host) {
			return nil, nil
		}
	}

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
		return nil, err
	}
	signature, matched := matchCloudNotFound(provider, first.status, first.body)
	if !matched {
		return nil, nil
	}
	second, err := m.fetch(ctx, anonymousClient, modifiedRaw)
	if err != nil {
		return nil, nil
	}
	secondSignature, reproduced := matchCloudNotFound(provider, second.status, second.body)
	if !reproduced || secondSignature.name != signature.name {
		return nil, nil
	}

	target := ctx.Target()
	return []*output.ResultEvent{{
		ModuleID:      ModuleID,
		RecordKind:    output.RecordKindCandidate,
		EvidenceGrade: output.EvidenceGradeDifferential,
		URL:           target,
		Matched:       target,
		Request:       first.request,
		Response:      first.response,
		AdditionalEvidence: []string{
			output.BuildEvidence("credential-free confirmation", second.request, second.response),
		},
		ExtractedResults: []string{
			fmt.Sprintf("Provider: %s", signature.provider),
			fmt.Sprintf("Structured error: %s", signature.name),
			fmt.Sprintf("Host: %s", host),
		},
		Info: output.Info{
			Name:        fmt.Sprintf("Dangling Cloud Storage Name Candidate: %s", signature.provider),
			Description: fmt.Sprintf("The provider-bound host %s reproducibly returned the structured %q resource-not-found response to an isolated credential-free client. This is a dangling-name candidate; actual namespace claimability and ownership were not tested.", host, signature.name),
			Severity:    severity.High,
			Confidence:  ModuleConfidence,
			Tags:        ModuleTags,
			Reference:   []string{"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover"},
		},
		Metadata: map[string]any{
			"provider_bound_host": true,
			"structured_error":    signature.name,
			"confirmation_rounds": 2,
			"claimability_tested": false,
			"resource_registered": false,
		},
	}}, nil
}

func (m *Module) fetch(ctx *httpmsg.HttpRequestResponse, client *http.Requester, raw []byte) (cloudCapture, error) {
	req := httpmsg.NewRequestResponseRaw(raw, ctx.Service())
	resp, _, err := client.Execute(req, http.Options{NoRedirects: true, NoClustering: true})
	if err != nil {
		return cloudCapture{}, err
	}
	defer resp.Close()
	if resp.Response() == nil || infra.IsBlockedResponse(resp) {
		return cloudCapture{}, nil
	}
	return cloudCapture{
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
