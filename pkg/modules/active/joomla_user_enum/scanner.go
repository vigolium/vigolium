package joomla_user_enum

import (
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	httpUtils "github.com/projectdiscovery/utils/http"
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

	diskSet := m.ds.Get(scanCtx.DedupMgr())
	if diskSet != nil && diskSet.IsSeen(host) {
		return nil, nil
	}

	var results []*output.ResultEvent

	// Vector 1: Registration form
	if result := m.probeRegistration(ctx, httpClient); result != nil {
		results = append(results, result)
	}

	// Vector 2: API user listing (Joomla 4+)
	if result := m.probeAPIUsers(ctx, httpClient); result != nil {
		results = append(results, result)
	}

	// Vector 3: Administrator login exposure
	if result := m.probeAdminLogin(ctx, httpClient); result != nil {
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
	fuzzedReq, err := httpmsg.ParseRawRequest(string(modifiedRaw))
	if err != nil {
		return nil, nil, err
	}
	fuzzedReq = fuzzedReq.WithService(ctx.Service())

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
	if err != nil {
		return nil, modifiedRaw, err
	}
	return resp, modifiedRaw, nil
}

func (m *Module) probeRegistration(ctx *httpmsg.HttpRequestResponse, httpClient *http.Requester) *output.ResultEvent {
	resp, _, err := m.sendGET(ctx, httpClient, "/index.php?option=com_users&view=registration")
	if err != nil {
		return nil
	}
	defer resp.Close()

	if resp.Response() == nil || resp.Response().StatusCode != 200 {
		return nil
	}

	body := resp.Body().String()

	// Check for registration form markers
	hasForm := strings.Contains(body, "jform[name]") || strings.Contains(body, "jform[username]") || strings.Contains(body, "jform[email")
	if !hasForm {
		return nil
	}

	urlx, _ := ctx.URL()
	return &output.ResultEvent{
		URL:     urlx.Scheme + "://" + urlx.Host + "/index.php?option=com_users&view=registration",
		Matched: urlx.Scheme + "://" + urlx.Host + "/index.php?option=com_users&view=registration",
		Info: output.Info{
			Name:        "Joomla User Registration Form Exposed",
			Description: "Joomla user registration form is publicly accessible, enabling account creation and potentially username enumeration via error messages",
			Severity:    severity.Low,
			Confidence:  severity.Certain,
			Tags:        []string{"cms", "joomla", "user-enumeration"},
			Reference:   []string{"https://docs.joomla.org/Security_Checklist"},
		},
		Metadata: map[string]any{
			"vector": "registration-form",
		},
	}
}

func (m *Module) probeAPIUsers(ctx *httpmsg.HttpRequestResponse, httpClient *http.Requester) *output.ResultEvent {
	resp, _, err := m.sendGET(ctx, httpClient, "/api/index.php/v1/users")
	if err != nil {
		return nil
	}
	defer resp.Close()

	if resp.Response() == nil || resp.Response().StatusCode != 200 {
		return nil
	}

	ct := strings.ToLower(resp.Response().Header.Get("Content-Type"))
	if !strings.Contains(ct, "json") {
		return nil
	}

	body := resp.Body().String()
	if !strings.Contains(body, `"type":"users"`) && !strings.Contains(body, `"type": "users"`) {
		return nil
	}

	urlx, _ := ctx.URL()
	return &output.ResultEvent{
		URL:      urlx.Scheme + "://" + urlx.Host + "/api/index.php/v1/users",
		Matched:  urlx.Scheme + "://" + urlx.Host + "/api/index.php/v1/users",
		Response: body,
		Info: output.Info{
			Name:        "Joomla API User Enumeration",
			Description: "Joomla Web Services API exposes user data anonymously at /api/index.php/v1/users",
			Severity:    severity.Medium,
			Confidence:  severity.Certain,
			Tags:        []string{"cms", "joomla", "user-enumeration", "api"},
			Reference:   []string{"https://developer.joomla.org/security-centre.html"},
		},
		Metadata: map[string]any{
			"vector": "web-services-api",
		},
	}
}

func (m *Module) probeAdminLogin(ctx *httpmsg.HttpRequestResponse, httpClient *http.Requester) *output.ResultEvent {
	resp, _, err := m.sendGET(ctx, httpClient, "/administrator/")
	if err != nil {
		return nil
	}
	defer resp.Close()

	if resp.Response() == nil {
		return nil
	}

	status := resp.Response().StatusCode
	// A 200 with login form = exposed, 403/401/WAF challenge = hardened
	if status != 200 {
		return nil
	}

	body := resp.Body().String()
	// Check for Joomla admin login form markers
	if !strings.Contains(body, "com_login") && !strings.Contains(body, "mod-login") && !strings.Contains(body, "task=login") {
		return nil
	}

	urlx, _ := ctx.URL()
	return &output.ResultEvent{
		URL:     urlx.Scheme + "://" + urlx.Host + "/administrator/",
		Matched: urlx.Scheme + "://" + urlx.Host + "/administrator/",
		Info: output.Info{
			Name:        "Joomla Administrator Login Exposed",
			Description: "Joomla administrator login is publicly accessible without WAF protection, IP restriction, or other access controls",
			Severity:    severity.Low,
			Confidence:  severity.Firm,
			Tags:        []string{"cms", "joomla", "admin-exposure"},
			Reference:   []string{"https://docs.joomla.org/Security_Checklist"},
		},
		Metadata: map[string]any{
			"vector": "admin-login",
		},
	}
}
