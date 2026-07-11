package joomla_user_enum

import (
	"encoding/json"
	"fmt"
	"strings"

	httpUtils "github.com/projectdiscovery/utils/http"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra"
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
			ModuleID, ModuleName, ModuleDesc, ModuleShort, ModuleConfirmation,
			ModuleSeverity, ModuleConfidence,
			modkit.ScanScopeRequest, modkit.AllInsertionPointTypes,
		),
		ds: dedup.LazyDiskSet("joomla_user_enum"),
	}
	m.ModuleTags = ModuleTags
	return m
}

func (m *Module) IncludesBaseCanProcess() bool { return false }

func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	if ctx == nil || ctx.Request() == nil {
		return false
	}
	return ctx.Response() != nil
}

func (m *Module) ScanPerRequest(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	service := ctx.Service()
	if service == nil {
		return nil, nil
	}
	host := service.Host()

	if scanCtx != nil {
		diskSet := m.ds.Get(scanCtx.DedupMgr())
		if diskSet != nil && diskSet.IsSeen(host) {
			return nil, nil
		}
	}
	cleanRaw, err := modkit.StripCredentialHeaders(ctx.Request().Raw())
	if err != nil {
		return nil, nil
	}
	anonymousClient, err := httpClient.CloneWithoutCredentials()
	if err != nil {
		return nil, nil
	}
	anonymousCtx := httpmsg.NewHttpRequestResponse(
		httpmsg.NewHttpRequestWithService(service, cleanRaw),
		ctx.Response(),
	)

	var results []*output.ResultEvent

	// Vector 1: Registration form
	if result := m.probeRegistration(anonymousCtx, anonymousClient); result != nil {
		results = append(results, result)
	}

	// Vector 2: API user listing (Joomla 4+)
	if result := m.probeAPIUsers(anonymousCtx, anonymousClient); result != nil {
		results = append(results, result)
	}

	// Vector 3: Administrator login exposure
	if result := m.probeAdminLogin(anonymousCtx, anonymousClient); result != nil {
		results = append(results, result)
	}

	return results, nil
}

func (m *Module) sendGET(ctx *httpmsg.HttpRequestResponse, httpClient *http.Requester, path string) (*httpUtils.ResponseChain, []byte, error) {
	modifiedRaw, err := httpmsg.SetMethod(ctx.Request().Raw(), "GET")
	if err != nil {
		return nil, nil, err
	}
	modifiedRaw, err = httpmsg.SetPath(modifiedRaw, path)
	if err != nil {
		return nil, nil, err
	}
	// modifiedRaw is internally built (well-formed), so wrap directly instead
	// of re-parsing on this hot path.
	fuzzedReq := httpmsg.NewRequestResponseRaw(modifiedRaw, ctx.Service())

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{NoRedirects: true, NoClustering: true})
	if err != nil {
		return nil, modifiedRaw, err
	}
	return resp, modifiedRaw, nil
}

func (m *Module) probeRegistration(ctx *httpmsg.HttpRequestResponse, httpClient *http.Requester) *output.ResultEvent {
	resp, raw, err := m.sendGET(ctx, httpClient, "/index.php?option=com_users&view=registration")
	if err != nil {
		return nil
	}
	defer resp.Close()

	if resp.Response() == nil || resp.Response().StatusCode != 200 || infra.IsBlockedResponse(resp) {
		return nil
	}

	body := resp.Body().String()

	markers, ok := modkit.MatchAllGroups(body, [][]string{
		{"member-registration", "com_users", "view=registration"},
		{"jform[name]", "jform[username]"},
		{"jform[email", "jform[password"},
	})
	if !ok {
		return nil
	}

	urlx, _ := ctx.URL()
	return &output.ResultEvent{
		ModuleID:         ModuleID,
		RecordKind:       output.RecordKindObservation,
		EvidenceGrade:    output.EvidenceGradeObservation,
		URL:              urlx.Scheme + "://" + urlx.Host + "/index.php?option=com_users&view=registration",
		Matched:          urlx.Scheme + "://" + urlx.Host + "/index.php?option=com_users&view=registration",
		Request:          string(raw),
		Response:         resp.FullResponseString(),
		ExtractedResults: markers,
		Info: output.Info{
			Name:        "Joomla Public Registration Feature Observed",
			Description: "A credential-free request reached a marker-confirmed Joomla registration form. Public registration is a supported feature; account creation and username-error differentials were not tested.",
			Severity:    severity.Info,
			Confidence:  severity.Certain,
			Tags:        []string{"cms", "joomla", "user-enumeration"},
			Reference:   []string{"https://docs.joomla.org/Security_Checklist"},
		},
		Metadata: map[string]any{
			"vector":                "registration-form",
			"credential_free":       true,
			"account_created":       false,
			"enumeration_confirmed": false,
		},
	}
}

func (m *Module) probeAPIUsers(ctx *httpmsg.HttpRequestResponse, httpClient *http.Requester) *output.ResultEvent {
	resp, raw, err := m.sendGET(ctx, httpClient, "/api/index.php/v1/users")
	if err != nil {
		return nil
	}
	defer resp.Close()

	if resp.Response() == nil || resp.Response().StatusCode != 200 || infra.IsBlockedResponse(resp) {
		return nil
	}

	ct := strings.ToLower(resp.Response().Header.Get("Content-Type"))
	if !strings.Contains(ct, "json") {
		return nil
	}

	body := resp.Body().String()
	count, labels, ok := parseJoomlaAPIUsers(body)
	if !ok {
		return nil
	}

	urlx, _ := ctx.URL()
	return &output.ResultEvent{
		ModuleID:         ModuleID,
		RecordKind:       output.RecordKindObservation,
		EvidenceGrade:    output.EvidenceGradeObservation,
		URL:              urlx.Scheme + "://" + urlx.Host + "/api/index.php/v1/users",
		Matched:          urlx.Scheme + "://" + urlx.Host + "/api/index.php/v1/users",
		Request:          string(raw),
		Response:         resp.FullResponseString(),
		ExtractedResults: labels,
		Info: output.Info{
			Name:        "Joomla Public API User Objects Observed",
			Description: fmt.Sprintf("Joomla Web Services returned %d structurally valid user object(s) without credentials. Public profile data may be intentional; private login identities were not established.", count),
			Severity:    severity.Info,
			Confidence:  severity.Certain,
			Tags:        []string{"cms", "joomla", "user-enumeration", "api"},
			Reference:   []string{"https://developer.joomla.org/security-centre.html"},
		},
		Metadata: map[string]any{
			"vector":                  "web-services-api",
			"count":                   count,
			"credential_free":         true,
			"private_accounts_proven": false,
		},
	}
}

func parseJoomlaAPIUsers(body string) (int, []string, bool) {
	var document struct {
		Data []struct {
			Type       string         `json:"type"`
			ID         string         `json:"id"`
			Attributes map[string]any `json:"attributes"`
		} `json:"data"`
	}
	if json.Unmarshal([]byte(body), &document) != nil || len(document.Data) == 0 {
		return 0, nil, false
	}
	var labels []string
	count := 0
	for _, resource := range document.Data {
		if resource.Type != "users" {
			continue
		}
		count++
		label := resource.ID
		for _, key := range []string{"name", "username"} {
			if value, ok := resource.Attributes[key].(string); ok && strings.TrimSpace(value) != "" {
				label = value
				break
			}
		}
		if label != "" {
			labels = append(labels, label)
		}
	}
	return count, labels, count > 0
}

func (m *Module) probeAdminLogin(ctx *httpmsg.HttpRequestResponse, httpClient *http.Requester) *output.ResultEvent {
	resp, raw, err := m.sendGET(ctx, httpClient, "/administrator/")
	if err != nil {
		return nil
	}
	defer resp.Close()

	if resp.Response() == nil || infra.IsBlockedResponse(resp) {
		return nil
	}

	status := resp.Response().StatusCode
	// A 200 with login form = exposed, 403/401/WAF challenge = hardened
	if status != 200 {
		return nil
	}

	body := resp.Body().String()
	markers, ok := modkit.MatchAllGroups(body, [][]string{
		{"com_login", "mod-login"},
		{"task=login", `name="username"`, `name="passwd"`, "form-login"},
	})
	if !ok {
		return nil
	}

	urlx, _ := ctx.URL()
	return &output.ResultEvent{
		ModuleID:         ModuleID,
		RecordKind:       output.RecordKindObservation,
		EvidenceGrade:    output.EvidenceGradeObservation,
		URL:              urlx.Scheme + "://" + urlx.Host + "/administrator/",
		Matched:          urlx.Scheme + "://" + urlx.Host + "/administrator/",
		Request:          string(raw),
		Response:         resp.FullResponseString(),
		ExtractedResults: markers,
		Info: output.Info{
			Name:        "Joomla Administrator Login Observed",
			Description: "A credential-free request reached a marker-confirmed Joomla administrator login. Login-page reachability does not prove absent WAF controls, weak credentials, or administrative access.",
			Severity:    severity.Info,
			Confidence:  severity.Firm,
			Tags:        []string{"cms", "joomla", "admin-exposure"},
			Reference:   []string{"https://docs.joomla.org/Security_Checklist"},
		},
		Metadata: map[string]any{
			"vector":                "admin-login",
			"credential_free":       true,
			"administrative_access": false,
			"credential_weakness":   false,
		},
	}
}
