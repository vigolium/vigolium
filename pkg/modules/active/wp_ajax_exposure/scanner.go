package wp_ajax_exposure

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// controlProbe captures the response to an admin-ajax.php call with a
// nonexistent action, used to fingerprint hosts that aren't actually
// WordPress (e.g., SPA wildcards returning index.html for every path).
type controlProbe struct {
	status   int
	bodyLen  int
	bodyHead string
}

func (c *controlProbe) matches(status int, body string) bool {
	if c == nil || c.bodyLen == 0 || len(body) == 0 {
		return false
	}
	if status != c.status {
		return false
	}
	diff := math.Abs(float64(len(body)-c.bodyLen)) / float64(c.bodyLen)
	if diff > 0.10 {
		return false
	}
	head := body
	if len(head) > 256 {
		head = head[:256]
	}
	return head == c.bodyHead
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
			modkit.ScanScopeRequest,
			modkit.AllInsertionPointTypes,
		),
		ds: dedup.LazyDiskSet("wp_ajax_exposure"),
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

	urlx, err := ctx.URL()
	if err != nil {
		return nil, nil
	}

	// Fingerprint check: hit admin-ajax.php with a random nonexistent action.
	// A real WordPress install returns "0" (or "-1"). An SPA wildcard or
	// non-WP host returns the same page it serves for any path — and a real
	// action probe will return that same page, giving false positives.
	control := m.fetchControlProbe(ctx, httpClient, urlx.Host)
	if control == nil {
		return nil, nil
	}
	wildcard, _ := scanCtx.WildcardProbe(ctx, httpClient)
	if wildcard.MatchesBody(control.status, []byte(control.bodyHead)) {
		// admin-ajax.php is returning the host's wildcard shell — not WP.
		return nil, nil
	}
	// Even without a wildcard match, if the control probe came back with a
	// "successful-looking" body, the host isn't behaving like WordPress.
	if !looksLikeWPControl(control) {
		return nil, nil
	}

	var results []*output.ResultEvent

	for _, action := range vulnerableActions {
		result := m.probeAction(ctx, httpClient, urlx.Scheme, urlx.Host, action, control)
		if result != nil {
			results = append(results, result)
		}
	}

	return results, nil
}

// fetchControlProbe sends a request with a synthetic action and snapshots the
// response for later comparison.
func (m *Module) fetchControlProbe(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	host string,
) *controlProbe {
	rndBytes := make([]byte, 8)
	if _, err := rand.Read(rndBytes); err != nil {
		return nil
	}
	action := "vigolium_noop_" + hex.EncodeToString(rndBytes)
	body := "action=" + action

	rawReq := "POST /wp-admin/admin-ajax.php HTTP/1.1\r\n" +
		"Host: " + host + "\r\n" +
		"Content-Type: application/x-www-form-urlencoded\r\n" +
		"User-Agent: Mozilla/5.0\r\n" +
		fmt.Sprintf("Content-Length: %d\r\n", len(body)) +
		"\r\n" +
		body

	fuzzedReq, err := httpmsg.ParseRawRequest(rawReq)
	if err != nil {
		return nil
	}
	fuzzedReq = fuzzedReq.WithService(ctx.Service())

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
	if err != nil || resp == nil || resp.Response() == nil {
		if resp != nil {
			resp.Close()
		}
		return nil
	}
	defer resp.Close()

	respBody := resp.Body().String()
	head := respBody
	if len(head) > 256 {
		head = head[:256]
	}
	return &controlProbe{
		status:   resp.Response().StatusCode,
		bodyLen:  len(respBody),
		bodyHead: head,
	}
}

// looksLikeWPControl returns true when the control-probe response is consistent
// with a real WordPress admin-ajax.php endpoint (small "0"/"-1" payload, or a
// short error message).
func looksLikeWPControl(c *controlProbe) bool {
	if c == nil {
		return false
	}
	// WordPress returns small bodies for unregistered actions ("0", "-1", or
	// a short JSON/text error). An SPA shell or static index.html will be
	// orders of magnitude larger.
	if c.bodyLen > 512 {
		return false
	}
	trimmed := strings.TrimSpace(c.bodyHead)
	if trimmed == "0" || trimmed == "-1" {
		return true
	}
	// Accept any small body that doesn't look like an HTML shell.
	lower := strings.ToLower(c.bodyHead)
	if strings.Contains(lower, "<!doctype") || strings.Contains(lower, "<html") {
		return false
	}
	return true
}

// genericErrorMarkers are substrings (lowercase) that identify a generic HTML
// error / challenge / SPA-shell page served by a CDN, WAF, or front-end router
// rather than by WordPress's admin-ajax. The reported false positive was
// help.grab.com answering every admin-ajax POST with a "load-failed … Refresh"
// HTML page; any of these in the body marks the response as untrusted.
var genericErrorMarkers = []string{
	"load-failed",
	"load_failed",
	"window.location.reload",
	"location.reload",
	"<!doctype",
	"<html",
	"</html>",
	"</body>",
	"please enable javascript",
	"enable javascript to run",
	"access denied",
	"request blocked",
	"are unable to process",
	"cloudflare",
	"captcha",
	"ray id",
}

// containsAny reports whether body contains any of the (lowercase) substrings.
func containsAny(body string, subs []string) bool {
	for _, s := range subs {
		if s != "" && strings.Contains(body, s) {
			return true
		}
	}
	return false
}

func (m *Module) probeAction(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scheme, host string,
	action ajaxAction,
	control *controlProbe,
) *output.ResultEvent {
	path := "/wp-admin/admin-ajax.php"
	body := "action=" + action.name

	rawReq := "POST " + path + " HTTP/1.1\r\n" +
		"Host: " + host + "\r\n" +
		"Content-Type: application/x-www-form-urlencoded\r\n" +
		"User-Agent: Mozilla/5.0\r\n" +
		fmt.Sprintf("Content-Length: %d\r\n", len(body)) +
		"\r\n" +
		body

	fuzzedReq, err := httpmsg.ParseRawRequest(rawReq)
	if err != nil {
		return nil
	}
	fuzzedReq = fuzzedReq.WithService(ctx.Service())

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
	if err != nil {
		return nil
	}
	defer resp.Close()

	if resp.Response() == nil {
		return nil
	}

	status := resp.Response().StatusCode
	respBody := resp.Body().String()

	// WordPress returns "0" for unregistered actions
	// A real handler returns something else
	if status != 200 {
		return nil
	}
	trimmed := strings.TrimSpace(respBody)
	if trimmed == "0" || trimmed == "-1" || trimmed == "" {
		return nil
	}

	// If this response is indistinguishable from the unregistered-action
	// control probe, the action isn't actually wired up — the server is
	// returning the same thing it returned for a junk action.
	if control.matches(status, respBody) {
		return nil
	}

	lowerBody := strings.ToLower(respBody)

	// Positive confirmation: the response must contain a substring that ties it
	// to THIS plugin/action. This is the core gate against false positives — a
	// generic error page contains none of these, while a genuinely exposed
	// nopriv handler echoes them even in its error/permission responses.
	matched, ok := modkit.MatchAllGroups(lowerBody, action.markers)
	if !ok {
		return nil
	}

	// Defense in depth: drop generic error / challenge / SPA-shell pages. A
	// CDN/WAF/app router serves a boilerplate HTML page (the help.grab.com
	// "load-failed … Refresh" page that produced a false positive is one) for
	// every admin-ajax POST regardless of action. If such a page also matched a
	// plugin token by coincidence, only trust it when it's clearly an
	// admin-ajax response rather than a router/error shell.
	if containsAny(lowerBody, genericErrorMarkers) && !strings.Contains(lowerBody, "admin-ajax") {
		return nil
	}

	targetURL := scheme + "://" + host + path + "?action=" + action.name

	sev := severity.High
	if action.sev != 0 {
		sev = action.sev
	}

	return &output.ResultEvent{
		URL:              targetURL,
		Matched:          targetURL,
		Request:          rawReq,
		Response:         respBody,
		ExtractedResults: append([]string{action.name, action.plugin}, matched...),
		Info: output.Info{
			Name:        fmt.Sprintf("WordPress AJAX Action Exposed: %s", action.name),
			Description: fmt.Sprintf("The wp_ajax_nopriv_%s action (plugin: %s) responds to unauthenticated requests. %s", action.name, action.plugin, action.desc),
			Severity:    sev,
			Confidence:  severity.Firm,
			Tags:        []string{"wordpress", "ajax", "plugin-vulnerability"},
		},
		Metadata: map[string]any{
			"action": action.name,
			"plugin": action.plugin,
		},
	}
}
