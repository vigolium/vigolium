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

// ScanPerRequest tests whether the host's session mechanism is permissive: it
// issues its own session cookie for a cookie-stripped request but then adopts an
// attacker-supplied value for that cookie without reissuing. Fails closed when no
// session cookie is issued (the host doesn't manage sessions here).
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

	// Step 2: present two independent attacker-chosen values; a permissive server
	// keeps each (no reissue) while a strict server regenerates its own.
	fixed1 := "vigfix" + utils.RandomString(24)
	fixed2 := "vigfix" + utils.RandomString(24)
	if !m.adoptsValue(ctx, httpClient, raw, name, fixed1) {
		return nil, nil
	}
	if !m.adoptsValue(ctx, httpClient, raw, name, fixed2) {
		return nil, nil
	}

	target := urlx.String()
	return []*output.ResultEvent{{
		ModuleID: ModuleID,
		URL:      target,
		Matched:  target,
		ExtractedResults: []string{
			"session_cookie=" + name,
			"behavior=server adopted attacker-supplied value without regenerating it (verified with 2 values)",
		},
		Info: output.Info{
			Name:        "Permissive Session Management (session fixation)",
			Description: fmt.Sprintf("The server issues its own %q session cookie for a fresh request but adopts an attacker-supplied value for it without regenerating a new one — confirmed with two independent values. An attacker can fix a victim's session ID and, because it is not regenerated, hijack the session after the victim authenticates.", name),
			Severity:    ModuleSeverity,
			Confidence:  ModuleConfidence,
			Tags:        ModuleTags,
		},
	}}, nil
}

// adoptsValue sends the request with the session cookie set to value and reports
// whether the server accepted it: a non-error status AND no reissue of the cookie
// with a different value.
func (m *Module) adoptsValue(
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
	reissued, present := setCookies[strings.ToLower(name)]
	if present && reissued != value {
		return false // server regenerated its own value — strict, not permissive
	}
	return true
}

// send issues raw and returns the status and the Set-Cookie name→value map.
func (m *Module) send(ctx *httpmsg.HttpRequestResponse, httpClient *http.Requester, raw []byte) (int, map[string]string, bool) {
	req := httpmsg.NewRequestResponseRaw(raw, ctx.Service())
	resp, _, err := httpClient.Execute(req, http.Options{NoClustering: true})
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
		set[strings.ToLower(c.Name)] = c.Value
	}
	return r.StatusCode, set, true
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
