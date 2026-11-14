package aem_default_credentials

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	aem "github.com/vigolium/vigolium/pkg/modules/infra/aem"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

const granitePath = "/libs/granite/core/content/login.html/j_security_check"
const felixPath = "/system/console/bundles"
const loginStatusPath = "/system/sling/loginstatus.json"

// cred is a default/demo AEM credential pair.
type cred struct{ user, pass string }

// creds is the curated default + Geometrixx demo credential list. Kept short to
// bound login attempts (and avoid account lockout).
var creds = []cred{
	{"admin", "admin"},
	{"author", "author"},
	{"grios", "password"},
	{"replication-receiver", "replication-receiver"},
	{"vgnadmin", "vgnadmin"},
	{"aparker@geometrixx.info", "aparker"},
	{"jdoe@geometrixx.info", "jdoe"},
	{"james.devore@spambob.com", "password"},
	{"matt.monroe@mailinator.com", "password"},
	{"aaron.mcdonald@mailinator.com", "password"},
	{"jason.werner@dodgit.com", "password"},
}

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
		ds: dedup.LazyDiskSet("aem_default_credentials"),
	}
	m.ModuleTags = ModuleTags
	return m
}

func (m *Module) IncludesBaseCanProcess() bool { return false }

func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	return ctx != nil && ctx.Request() != nil
}

func (m *Module) ScanPerHost(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	urlx, err := ctx.URL()
	if err != nil {
		return nil, nil
	}
	host := urlx.Host

	diskSet := m.ds.Get(scanCtx.DedupMgr())
	if !modkit.BeginHostProbe(scanCtx, httpClient, diskSet, host) {
		return nil, nil
	}

	if !aem.ConfirmAEM(ctx, httpClient, scanCtx) {
		return nil, nil
	}

	baseURL := urlx.Scheme + "://" + urlx.Host
	var results []*output.ResultEvent
	if res := m.checkGranite(ctx, httpClient, baseURL); res != nil {
		results = append(results, res)
	}
	if res := m.checkFelix(ctx, httpClient, baseURL); res != nil {
		results = append(results, res)
	}
	if res := m.checkLoginStatus(ctx, httpClient, baseURL); res != nil {
		results = append(results, res)
	}
	return results, nil
}

// checkLoginStatus tries HTTP Basic against the LoginStatusServlet, which reports
// authenticated=true&userid=<user> for valid credentials and has no brute-force
// protection. The negative control must NOT authenticate; if it does (e.g. an
// authenticated session cookie is present on the observed request), the check
// fails closed so a cookie is never mistaken for a default credential.
func (m *Module) checkLoginStatus(ctx *httpmsg.HttpRequestResponse, client *http.Requester, baseURL string) *output.ResultEvent {
	if loginStatusSucceeds(ctx, client, modkit.FreshCanary(), modkit.FreshCanary()) {
		return nil
	}
	for _, c := range creds {
		if !loginStatusSucceeds(ctx, client, c.user, c.pass) {
			continue
		}
		if !loginStatusSucceeds(ctx, client, c.user, c.pass) {
			continue
		}
		return m.build("Sling LoginStatus (Basic auth)", loginStatusPath, c, baseURL)
	}
	return nil
}

func loginStatusSucceeds(ctx *httpmsg.HttpRequestResponse, client *http.Requester, user, pass string) bool {
	res := basicAuthGet(ctx, client, loginStatusPath, user, pass)
	if !res.OK || res.Status != 200 {
		return false
	}
	return aem.HasAny(res.Body, "authenticated=true", `"authenticated":true`)
}

// checkGranite tries the Sling/Granite j_security_check login. It first confirms
// a deliberately-wrong credential is rejected (so an endpoint that issues a token
// for anything cannot forge a finding), then tries each default credential and
// re-confirms the winner.
func (m *Module) checkGranite(ctx *httpmsg.HttpRequestResponse, client *http.Requester, baseURL string) *output.ResultEvent {
	// Negative control — a random credential must NOT authenticate.
	if graniteLoginSucceeds(ctx, client, baseURL, modkit.FreshCanary(), modkit.FreshCanary()) {
		return nil
	}
	for _, c := range creds {
		if !graniteLoginSucceeds(ctx, client, baseURL, c.user, c.pass) {
			continue
		}
		// Reproduce the successful login before reporting.
		if !graniteLoginSucceeds(ctx, client, baseURL, c.user, c.pass) {
			continue
		}
		return m.build("Granite login (j_security_check)", granitePath, c, baseURL)
	}
	return nil
}

func graniteLoginSucceeds(ctx *httpmsg.HttpRequestResponse, client *http.Requester, baseURL, user, pass string) bool {
	body := "_charset_=utf-8&j_username=" + url.QueryEscape(user) +
		"&j_password=" + url.QueryEscape(pass) + "&j_validate=true"
	headers := map[string]string{
		"Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
		"Referer":      baseURL + "/",
		"Origin":       baseURL,
	}
	res := aem.Post(ctx, client, granitePath, body, headers)
	if !res.OK {
		return false
	}
	// AEM issues a login-token (Set-Cookie and echoed in the body) on success and
	// returns invalid_login / session_timed_out on failure.
	setCookie := ""
	if res.Header != nil {
		setCookie = res.Header.Get("Set-Cookie")
	}
	hasToken := strings.Contains(setCookie, "login-token=") || strings.Contains(res.Body, "login-token=")
	failed := strings.Contains(res.Body, "invalid_login") || strings.Contains(res.Body, "session_timed_out")
	return hasToken && !failed && (res.Status == 200 || res.Status == 302)
}

// checkFelix tries the Felix/OSGi Web Console with HTTP Basic. The negative
// control must return the 401 challenge (an unauthenticated 200 console is an
// exposure the console module reports, not a default-credential finding).
func (m *Module) checkFelix(ctx *httpmsg.HttpRequestResponse, client *http.Requester, baseURL string) *output.ResultEvent {
	if felixLoginSucceeds(ctx, client, modkit.FreshCanary(), modkit.FreshCanary()) {
		return nil
	}
	for _, c := range creds {
		if !felixLoginSucceeds(ctx, client, c.user, c.pass) {
			continue
		}
		if !felixLoginSucceeds(ctx, client, c.user, c.pass) {
			continue
		}
		return m.build("Felix/OSGi Web Console", felixPath, c, baseURL)
	}
	return nil
}

// basicAuthGet issues a GET to path with an HTTP Basic Authorization header for the
// given credentials, reusing the observed request's other headers.
func basicAuthGet(ctx *httpmsg.HttpRequestResponse, client *http.Requester, path, user, pass string) aem.ProbeResult {
	basic := base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
	return aem.Get(ctx, client, path, map[string]string{"Authorization": "Basic " + basic})
}

func felixLoginSucceeds(ctx *httpmsg.HttpRequestResponse, client *http.Requester, user, pass string) bool {
	res := basicAuthGet(ctx, client, felixPath, user, pass)
	if !res.OK || res.Status != 200 {
		return false
	}
	return strings.Contains(res.Body, "Web Console") &&
		(strings.Contains(res.Body, "Adobe Experience Manager") || strings.Contains(res.Body, "Bundles"))
}

func (m *Module) build(endpoint, path string, c cred, baseURL string) *output.ResultEvent {
	matchedURL := baseURL + path
	desc := fmt.Sprintf(
		"AEM %s accepts the default credential %s:%s (a deliberately-wrong credential was rejected first, and the login reproduced).",
		endpoint, c.user, c.pass,
	)
	return &output.ResultEvent{
		ModuleID:      ModuleID,
		Host:          aem.HostFromBase(baseURL),
		URL:           matchedURL,
		Matched:       matchedURL,
		MatcherStatus: true,
		ExtractedResults: []string{
			"endpoint: " + endpoint,
			"credential: " + c.user + ":" + c.pass,
		},
		Info: output.Info{
			Name:        "AEM Default Credentials (" + c.user + ":" + c.pass + ")",
			Description: desc,
			Severity:    severity.High,
			Confidence:  severity.Certain,
			Tags:        []string{"aem", "adobe", "default-credentials", "auth"},
			Reference: []string{
				"https://helpx.adobe.com/experience-manager/6-5/sites/administering/using/security-checklist.html",
			},
		},
	}
}
