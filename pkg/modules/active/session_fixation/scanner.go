package session_fixation

import (
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/spitolas/loginsig"
	"github.com/vigolium/vigolium/pkg/utils"
)

// Module implements the Session Fixation active scanner.
type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new Session Fixation module.
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
			modkit.ScanScopeRequest,
			modkit.AllInsertionPointTypes,
		),
		ds: dedup.LazyDiskSet("session_fixation"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerRequest tests whether the host explicitly adopts an attacker-chosen
// session value. Silence is not adoption: a server may ignore an unknown cookie
// and serve an anonymous response without issuing a replacement. We therefore
// require the server to Set-Cookie the exact supplied value on two independent
// probes. This is a candidate unless the observed request is itself a successful
// authentication transition, in which case preservation through login confirms
// the fixation condition.
func (m *Module) ScanPerRequest(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	urlx, err := ctx.URL()
	if err != nil {
		return nil, nil
	}

	diskSet := m.ds.Get(scanCtx.DedupMgr())
	hostKey := urlx.Host
	if diskSet != nil && diskSet.IsSeen(hostKey) {
		return nil, nil
	}

	raw := ctx.Request().Raw()

	// Step 1: confirm the server ISSUES a session for a cookie-stripped request,
	// and learn the session cookie name. This is the technology gate — a host that
	// never sets a session cookie is not tested.
	stripped, hadCookie := stripCookieHeader(raw)
	if !hadCookie {
		stripped = raw
	}
	status0, set0, ok0 := m.send(ctx, httpClient, stripped)
	if !ok0 || status0 >= 400 {
		return nil, nil
	}
	name := firstSessionCookie(set0)
	if name == "" {
		return nil, nil // server issues no session cookie here — fail closed
	}

	// Step 2: present two independent attacker-chosen values. The server must
	// explicitly Set-Cookie each exact value; omission means unknown/ignored, not
	// accepted.
	fixed1 := "vigfix" + utils.RandomString(24)
	fixed2 := "vigfix" + utils.RandomString(24)
	if !m.explicitlyAdoptsValue(ctx, httpClient, raw, name, fixed1) {
		return nil, nil
	}
	if !m.explicitlyAdoptsValue(ctx, httpClient, raw, name, fixed2) {
		return nil, nil
	}

	target := urlx.String()
	kind := output.RecordKindCandidate
	grade := output.EvidenceGradeCandidate
	nameText := "Attacker-Chosen Session ID Explicitly Adopted"
	description := fmt.Sprintf("The server explicitly returned the attacker-supplied %q cookie value unchanged for two independent values. This proves permissive session-ID adoption, but session fixation still requires confirmation that the ID survives authentication or a privilege transition.", name)
	if isSuccessfulAuthenticationTransition(ctx) {
		kind = output.RecordKindFinding
		grade = output.EvidenceGradeBypass
		nameText = "Session Fixation Across Authentication"
		description = fmt.Sprintf("The authentication request explicitly preserved two attacker-chosen %q cookie values instead of rotating to server-generated identifiers. The attacker-controlled session identifier therefore survives the authentication transition.", name)
	}
	return []*output.ResultEvent{{
		ModuleID:      ModuleID,
		URL:           target,
		Matched:       target,
		RecordKind:    kind,
		EvidenceGrade: grade,
		ExtractedResults: []string{
			"session_cookie=" + name,
			"behavior=server explicitly Set-Cookie'd two attacker-supplied values unchanged",
		},
		Info: output.Info{
			Name:        nameText,
			Description: description,
			Severity:    ModuleSeverity,
			Confidence:  ModuleConfidence,
			Tags:        ModuleTags,
		},
		Metadata: map[string]any{
			"session_cookie":            name,
			"explicit_adoption_rounds":  2,
			"authentication_transition": kind == output.RecordKindFinding,
		},
	}}, nil
}

// explicitlyAdoptsValue requires affirmative server evidence: Set-Cookie must
// return the exact attacker-chosen value. A successful response with no
// Set-Cookie is ambiguous because the server may simply have ignored the value.
func (m *Module) explicitlyAdoptsValue(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	raw []byte,
	name, value string,
) bool {
	modified, err := httpmsg.SetCookie(raw, name, value)
	if err != nil {
		return false
	}
	status, setCookies, ok := m.send(ctx, httpClient, modified)
	if !ok || status >= 400 {
		return false
	}
	reissued, present := cookieValue(setCookies, name)
	return present && reissued == value
}

func isSuccessfulAuthenticationTransition(ctx *httpmsg.HttpRequestResponse) bool {
	if ctx == nil || ctx.Request() == nil || !ctx.HasResponse() {
		return false
	}
	method := strings.ToUpper(ctx.Request().Method())
	if method != "POST" && method != "PUT" && method != "PATCH" {
		return false
	}
	urlx, err := ctx.URL()
	if err != nil || !loginsig.LooksLikeLoginURL(urlx.URL) {
		return false
	}
	rawLower := strings.ToLower(string(ctx.Request().Raw()))
	if !strings.Contains(rawLower, "password") && !strings.Contains(rawLower, "passwd") && !strings.Contains(rawLower, "credential") {
		return false
	}
	resp := ctx.Response()
	if resp.StatusCode() < 200 || resp.StatusCode() >= 400 || loginsig.BodyLooksLikeLogin(resp.Body()) {
		return false
	}
	bodyLower := strings.ToLower(resp.BodyToString())
	for _, failure := range []string{"invalid password", "invalid credentials", "login failed", "authentication failed", "unauthorized"} {
		if strings.Contains(bodyLower, failure) {
			return false
		}
	}
	location := strings.ToLower(resp.Header("Location"))
	if location != "" && !strings.Contains(location, "login") && !strings.Contains(location, "signin") {
		return true
	}
	for _, success := range []string{`"authenticated":true`, `"access_token"`, `"token"`, "welcome", "dashboard", "logout", "sign out"} {
		if strings.Contains(bodyLower, success) {
			return true
		}
	}
	return false
}

// send issues raw and returns the status and the Set-Cookie name→value map.
func (m *Module) send(ctx *httpmsg.HttpRequestResponse, httpClient *http.Requester, raw []byte) (int, map[string]string, bool) {
	req := httpmsg.NewRequestResponseRaw(raw, ctx.Service())
	// Use the raw transport so the requester's cookie jar cannot merge the
	// server-generated technology-gate cookie into attacker-value probes. Each
	// probe must carry exactly the Cookie header constructed above.
	resp, _, err := httpClient.Execute(req, http.Options{NoClustering: true, RawRequest: true})
	if err != nil {
		return 0, nil, false
	}
	defer resp.Close()
	r := resp.Response()
	if r == nil {
		return 0, nil, false
	}
	// r is a stdlib *http.Response, so use its parsed cookies rather than
	// re-parsing Set-Cookie by hand.
	set := map[string]string{}
	for _, c := range r.Cookies() {
		// Preserve the wire spelling. Cookie names are case-sensitive, so
		// lower-casing SESSIONID and then replaying sessionid tests a different
		// cookie on compliant servers.
		set[c.Name] = c.Value
	}
	return r.StatusCode, set, true
}

func cookieValue(set map[string]string, name string) (string, bool) {
	for cookieName, value := range set {
		if cookieName == name {
			return value, true
		}
	}
	return "", false
}

// firstSessionCookie returns the first session-looking cookie name from a
// Set-Cookie map, or "".
func firstSessionCookie(set map[string]string) string {
	for n := range set {
		if infra.IsSessionCookieName(n) {
			return n
		}
	}
	return ""
}

// stripCookieHeader removes the Cookie header entirely. had is true if one was
// present.
func stripCookieHeader(raw []byte) (out []byte, had bool) {
	stripped, err := httpmsg.RemoveHeader(raw, "Cookie")
	if err != nil {
		return raw, false
	}
	return stripped, len(stripped) != len(raw)
}
