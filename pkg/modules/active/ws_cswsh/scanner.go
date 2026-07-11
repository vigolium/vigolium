package ws_cswsh

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	vighttp "github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/vigolium/vigolium/pkg/utils"
)

var wsHeaders = []struct{ name, value string }{
	{"Upgrade", "websocket"},
	{"Connection", "Upgrade"},
	{"Sec-WebSocket-Version", "13"},
}

type originTest struct {
	label                  string
	kind                   string
	removeHeader           bool
	requiresControlledHost bool
	buildOrigin            func(host string) string
}

var originTests = []originTest{
	{
		label:       "arbitrary cross-site origin",
		kind:        "cross-site",
		buildOrigin: func(string) string { return "https://evil.example.com" },
	},
	{
		label:       "opaque null origin",
		kind:        "null",
		buildOrigin: func(string) string { return "null" },
	},
	{
		label:                  "untrusted subdomain origin",
		kind:                   "subdomain",
		requiresControlledHost: true,
		buildOrigin: func(host string) string {
			return "https://attacker." + host
		},
	},
	{
		label:        "missing Origin header",
		kind:         "missing",
		removeHeader: true,
		buildOrigin:  func(string) string { return "" },
	},
}

var credentialHeaders = []string{
	"Authorization", "Proxy-Authorization", "Cookie", "X-API-Key", "Api-Key",
	"X-Api-Token", "X-Auth-Token", "X-Access-Token", "X-Session-Token",
}

type credentialPosture struct {
	present                      bool
	likelySession                bool
	crossSiteBrowserSessionKnown bool
	names                        []string
}

type upgradeAttempt struct {
	accepted bool
	status   int
	request  string
	response string
}

type upgradeEvidence struct {
	first        upgradeAttempt
	confirmation upgradeAttempt
}

type acceptedScenario struct {
	test                originTest
	origin              string
	evidence            upgradeEvidence
	credentialDependent bool
	credentialControl   upgradeEvidence
	browserConfirmed    bool
}

// Module implements an active scanner for Cross-Site WebSocket Hijacking.
type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new CSWSH scanner module.
func New() *Module {
	m := &Module{
		BaseActiveModule: modkit.NewBaseActiveModule(
			ModuleID, ModuleName, ModuleDesc, ModuleShort, ModuleConfirmation,
			ModuleSeverity, ModuleConfidence,
			modkit.ScanScopeRequest,
			modkit.AllInsertionPointTypes,
		),
		ds: dedup.LazyDiskSet("ws_cswsh"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerRequest distinguishes origin-policy capability from a credentialed
// browser exploit. It never sends WebSocket frames or application messages.
func (m *Module) ScanPerRequest(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *vighttp.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	if ctx == nil || ctx.Request() == nil || httpClient == nil {
		return nil, nil
	}
	urlx, err := ctx.URL()
	if err != nil || utils.IsMediaAndJSURL(urlx.EscapedPath()) {
		return nil, nil
	}

	if scanCtx != nil {
		diskSet := m.ds.Get(scanCtx.DedupMgr())
		hash := utils.Sha1(fmt.Sprintf("%s%s", urlx.Host, urlx.Path))
		if diskSet != nil && diskSet.IsSeen(hash) {
			return nil, nil
		}
	}

	legitimateOrigin := fmt.Sprintf("%s://%s", urlx.Scheme, urlx.Host)
	if _, ok := m.confirmUpgrade(ctx, httpClient, legitimateOrigin, false, false, true); !ok {
		return nil, nil
	}

	posture := inspectCredentialPosture(ctx, scanCtx)
	anonymousClient, _ := httpClient.CloneWithoutCredentials()
	hostname := ctx.Service().Host()

	var accepted []acceptedScenario
	for _, test := range originTests {
		if test.requiresControlledHost && (net.ParseIP(hostname) != nil || !strings.Contains(hostname, ".")) {
			continue
		}
		origin := test.buildOrigin(hostname)
		evidence, ok := m.confirmUpgrade(ctx, httpClient, origin, test.removeHeader, false, true)
		if !ok {
			continue
		}

		scenario := acceptedScenario{test: test, origin: origin, evidence: evidence}
		// A missing Origin is common for non-browser clients and is not itself a
		// browser CSWSH path. Credential controls are only meaningful for origins a
		// browser can actually emit.
		if posture.present && anonymousClient != nil && test.kind != "missing" {
			control, rejected := m.confirmUpgrade(ctx, anonymousClient, origin, false, true, false)
			if rejected {
				scenario.credentialDependent = true
				scenario.credentialControl = control
				scenario.browserConfirmed = posture.crossSiteBrowserSessionKnown && (test.kind == "cross-site" || test.kind == "null")
			}
		}
		accepted = append(accepted, scenario)
	}

	if len(accepted) == 0 {
		return nil, nil
	}
	return []*output.ResultEvent{m.result(urlx.String(), posture, accepted)}, nil
}

func inspectCredentialPosture(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) credentialPosture {
	var posture credentialPosture
	if ctx == nil || ctx.Request() == nil {
		return posture
	}

	if value := strings.TrimSpace(ctx.Request().Header("Cookie")); value != "" {
		posture.present = true
		for _, name := range modkit.RequestCookieNames(value) {
			posture.names = append(posture.names, "cookie:"+name)
			if modkit.LikelySessionCookie(name) {
				posture.likelySession = true
			}
		}
	}
	for _, name := range credentialHeaders {
		if strings.EqualFold(name, "Cookie") {
			continue
		}
		if strings.TrimSpace(ctx.Request().Header(name)) != "" {
			posture.present = true
			posture.names = append(posture.names, "header:"+name)
		}
	}

	if scanCtx == nil {
		return posture
	}
	scanCtx.ObserveResponseCookies(ctx)
	for _, policy := range scanCtx.RequestCookiePolicies(ctx) {
		if !modkit.LikelySessionCookie(policy.Name) {
			continue
		}
		posture.likelySession = true
		if policy.SameSite == "none" && policy.Secure {
			posture.crossSiteBrowserSessionKnown = true
		}
	}
	return posture
}

// confirmUpgrade requires two fresh, key-bound handshakes. expectAccepted=false
// is the negative credential control and succeeds only when both responses
// explicitly decline the upgrade; transport errors and malformed 101s fail
// closed rather than becoming proof of authentication.
func (m *Module) confirmUpgrade(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *vighttp.Requester,
	origin string,
	removeOrigin, stripCredentials, expectAccepted bool,
) (upgradeEvidence, bool) {
	first, err := m.tryUpgrade(ctx, httpClient, origin, removeOrigin, stripCredentials)
	if err != nil || !attemptMatches(first, expectAccepted) {
		return upgradeEvidence{}, false
	}
	second, err := m.tryUpgrade(ctx, httpClient, origin, removeOrigin, stripCredentials)
	if err != nil || !attemptMatches(second, expectAccepted) {
		return upgradeEvidence{}, false
	}
	return upgradeEvidence{first: first, confirmation: second}, true
}

func attemptMatches(attempt upgradeAttempt, expectAccepted bool) bool {
	if expectAccepted {
		return attempt.accepted
	}
	return !attempt.accepted && attempt.status > 0 && attempt.status != 101
}

func (m *Module) tryUpgrade(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *vighttp.Requester,
	origin string,
	removeOrigin, stripCredentials bool,
) (upgradeAttempt, error) {
	modified := append([]byte(nil), ctx.Request().Raw()...)
	var err error
	modified, err = httpmsg.SetMethod(modified, "GET")
	if err != nil {
		return upgradeAttempt{}, err
	}
	modified, err = httpmsg.ClearBody(modified)
	if err != nil {
		return upgradeAttempt{}, err
	}
	if stripCredentials {
		for _, name := range credentialHeaders {
			modified, err = httpmsg.RemoveHeader(modified, name)
			if err != nil {
				return upgradeAttempt{}, err
			}
		}
	}
	for _, header := range wsHeaders {
		modified, err = httpmsg.AddOrReplaceHeader(modified, header.name, header.value)
		if err != nil {
			return upgradeAttempt{}, err
		}
	}
	key, err := newWebSocketKey()
	if err != nil {
		return upgradeAttempt{}, err
	}
	modified, err = httpmsg.AddOrReplaceHeader(modified, "Sec-WebSocket-Key", key)
	if err != nil {
		return upgradeAttempt{}, err
	}
	if removeOrigin {
		modified, err = httpmsg.RemoveHeader(modified, "Origin")
	} else {
		modified, err = httpmsg.AddOrReplaceHeader(modified, "Origin", origin)
	}
	if err != nil {
		return upgradeAttempt{}, err
	}

	fuzzedReq := httpmsg.NewRequestResponseRaw(modified, ctx.Service())
	resp, _, err := httpClient.Execute(fuzzedReq, vighttp.Options{NoRedirects: true, NoClustering: true})
	if err != nil {
		return upgradeAttempt{}, err
	}
	defer resp.Close()

	attempt := upgradeAttempt{request: string(modified), response: resp.FullResponseString()}
	if resp.Response() != nil {
		attempt.status = resp.Response().StatusCode
		attempt.accepted = infra.IsWebSocketHandshakeForKey(resp, key)
	}
	return attempt, nil
}

func newWebSocketKey() (string, error) {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(nonce), nil
}

func (m *Module) result(target string, posture credentialPosture, accepted []acceptedScenario) *output.ResultEvent {
	kind := output.RecordKindObservation
	grade := output.EvidenceGradeObservation
	sev := severity.Info
	name := "WebSocket Origin Policy Observation"

	var acceptedLabels, dependentLabels, browserLabels []string
	var primary upgradeEvidence
	var credentialControl *upgradeEvidence
	primaryRank := -1
	for _, scenario := range accepted {
		rank := 0
		acceptedLabels = append(acceptedLabels, scenario.test.label)
		if scenario.test.kind != "missing" && kind == output.RecordKindObservation {
			rank = 1
			kind = output.RecordKindCandidate
			grade = output.EvidenceGradeCandidate
			sev = severity.Medium
			name = "Cross-Site WebSocket Hijacking Candidate"
		}
		if scenario.credentialDependent {
			rank = 2
			dependentLabels = append(dependentLabels, scenario.test.label)
			kind = output.RecordKindCandidate
			grade = output.EvidenceGradeDifferential
			sev = severity.Medium
			name = "Credential-Dependent WebSocket Origin Bypass Candidate"
			control := scenario.credentialControl
			credentialControl = &control
		}
		if scenario.browserConfirmed {
			rank = 3
			browserLabels = append(browserLabels, scenario.test.label)
			kind = output.RecordKindFinding
			grade = output.EvidenceGradeBypass
			sev = ModuleSeverity
			name = "Credentialed Cross-Site WebSocket Handshake Confirmed"
		}
		if rank > primaryRank {
			primary = scenario.evidence
			primaryRank = rank
		}
	}

	description := "The endpoint reproducibly accepted one or more non-matching Origin variants. This is an origin-policy security primitive; public or token-authenticated WebSockets may intentionally accept arbitrary origins, and no authenticated application message or action was demonstrated."
	if len(dependentLabels) > 0 {
		description = "The endpoint reproducibly accepted a non-matching Origin with the observed credentials and rejected the same handshake after all credentials were removed. This proves credential-dependent origin acceptance, but browser delivery of the credential or application-level impact was not fully established."
	}
	if len(browserLabels) > 0 {
		description = "The endpoint reproducibly accepted a non-matching browser Origin with a known SameSite=None; Secure session cookie and rejected the same handshake from an isolated credential-free client. This confirms a credentialed cross-site handshake. No WebSocket message or state-changing action was sent."
	}
	if kind == output.RecordKindObservation {
		description = "The endpoint reproducibly accepted a handshake without an Origin header. Non-browser WebSocket clients commonly omit Origin, so this is a hardening observation rather than evidence that a malicious web page can hijack a session."
	}

	additional := []string{
		output.BuildEvidence("fresh-key confirmation", primary.confirmation.request, primary.confirmation.response),
	}
	if credentialControl != nil {
		additional = append(additional,
			output.BuildEvidence("credential-free negative control", credentialControl.first.request, credentialControl.first.response),
			output.BuildEvidence("credential-free control confirmation", credentialControl.confirmation.request, credentialControl.confirmation.response),
		)
	}

	return &output.ResultEvent{
		ModuleID:           ModuleID,
		RecordKind:         kind,
		EvidenceGrade:      grade,
		URL:                target,
		Matched:            target,
		MatcherStatus:      true,
		Request:            primary.first.request,
		Response:           primary.first.response,
		AdditionalEvidence: additional,
		ExtractedResults: []string{
			"Accepted variants: " + strings.Join(acceptedLabels, ", "),
			"Credential-dependent variants: " + strings.Join(dependentLabels, ", "),
			"Browser-credential-confirmed variants: " + strings.Join(browserLabels, ", "),
		},
		Info: output.Info{
			Name:        name,
			Description: description,
			Severity:    sev,
			Confidence:  ModuleConfidence,
			Tags:        ModuleTags,
			Reference:   []string{"https://owasp.org/www-community/attacks/csrf"},
		},
		Metadata: map[string]any{
			"accepted_origin_variants":          acceptedLabels,
			"credential_dependent_variants":     dependentLabels,
			"browser_confirmed_variants":        browserLabels,
			"credential_names":                  posture.names,
			"likely_session_credential":         posture.likelySession,
			"cross_site_cookie_policy_observed": posture.crossSiteBrowserSessionKnown,
			"application_message_sent":          false,
			"fresh_handshake_keys":              true,
		},
	}
}
