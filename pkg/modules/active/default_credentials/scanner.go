package default_credentials

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
)

// credentialResponse holds extracted values from a login attempt response.
//
// body is the response BODY only (not the full response string). Every
// similarity/length comparison in this module runs against body — never the
// headers — because a login endpoint typically issues a fresh session cookie,
// a per-request request-id, and a clock-driven Date on every POST (including
// failed ones). Comparing full response strings lets those volatile headers
// manufacture a phantom "difference" between two identical-meaning rejections.
// raw keeps the full response string (headers+body) for evidence and edge-block
// detection only.
type credentialResponse struct {
	statusCode   int
	body         string
	raw          string
	location     string
	hasSetCookie bool
	blocked      bool // WAF/CDN block or challenge — carries no auth signal
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
		ds: dedup.LazyDiskSet("default_credentials"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// IncludesBaseCanProcess returns false because this module uses custom CanProcess.
func (m *Module) IncludesBaseCanProcess() bool { return false }

// CanProcess returns true only for POST requests with form-encoded or JSON bodies.
func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	if ctx == nil || ctx.Request() == nil {
		return false
	}

	// Only POST requests
	if ctx.Request().Method() != "POST" {
		return false
	}

	ct := strings.ToLower(ctx.Request().Header("Content-Type"))
	return strings.Contains(ct, "application/x-www-form-urlencoded") ||
		strings.Contains(ct, "application/json")
}

// ScanPerHost tests default credentials on detected login endpoints.
func (m *Module) ScanPerHost(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	service := ctx.Service()
	if service == nil {
		return nil, nil
	}

	// Dedup by host
	if !modkit.BeginHostProbeFor(scanCtx, httpClient, &m.ds, ctx) {
		return nil, nil
	}

	// Detect login endpoint
	endpoint := detectLoginEndpoint(ctx)
	if endpoint == nil {
		return nil, nil
	}

	// Check for CAPTCHA in original response
	if ctx.Response() != nil {
		origBody := ctx.Response().BodyToString()
		if hasCAPTCHA(origBody) {
			return nil, nil
		}
	}

	// Establish a failed-login baseline from TWO independent invalid-credential
	// probes. This does double duty: it captures what a generic rejected login
	// looks like, and — by requiring the two probes to agree — proves the endpoint
	// is stable enough that a later "success" differential can be trusted. A login
	// page that varies per request (rotating CSRF token, dynamic chrome) would
	// otherwise manufacture a phantom success. A single anomalous baseline can no
	// longer poison every comparison.
	baseline, err := m.sendCredentials(ctx, httpClient, endpoint,
		"vigolium-invalid-user-7a3f", "vigolium-invalid-pass-9b2e")
	if err != nil {
		return nil, err
	}
	if baseline.blocked {
		return nil, nil // WAF/CDN fronting the login — no reliable auth signal
	}
	// A captcha gate fronting the login makes credential testing meaningless: the
	// app rejects every attempt on the captcha *before* it ever checks the
	// credentials, returning the same response for admin/admin and random junk
	// alike. The gate often only surfaces in the POST response (a flash error in a
	// Set-Cookie, an error body), not the originally-observed page — so inspect the
	// full failed-login probe, not just ctx's response.
	if probeShowsCaptchaGate(baseline) {
		return nil, nil
	}

	time.Sleep(500 * time.Millisecond)
	baseline2, err := m.sendCredentials(ctx, httpClient, endpoint,
		"vigolium-decoy-user-2c8d", "vigolium-decoy-pass-5f1a")
	if err != nil {
		return nil, err
	}
	// The two failed-login probes must be equivalent (same status, redirect target,
	// and body): if they disagree the login surface is too dynamic to trust a later
	// "success" differential.
	if baseline2.blocked || probeShowsCaptchaGate(baseline2) || !responsesEquivalent(baseline, baseline2) {
		return nil, nil // login surface too volatile (or blocked/captcha-gated) to trust a differential
	}

	// Test credential pairs
	var results []*output.ResultEvent
	for _, cred := range defaultCredentials {
		time.Sleep(500 * time.Millisecond)

		cr, err := m.sendCredentials(ctx, httpClient, endpoint, cred.username, cred.password)
		if err != nil {
			if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
				return results, nil
			}
			continue
		}

		// A WAF/CDN block is neither a success nor a lockout — it is the edge, not
		// the application. Skip it without ending the sweep.
		if cr.blocked {
			continue
		}

		// Check for lockout
		if isLockout(cr.body) {
			return results, nil // Stop testing
		}

		if !isLoginSuccess(cr, baseline) {
			continue
		}

		// Confirm before reporting: the verdict must reproduce on a re-send, and
		// the "successful" response must be materially distinct from a freshly
		// fetched invalid-credential response (a negative control). This rejects
		// both transient one-off differentials and plain login-page variance that
		// merely looks different from the original baseline.
		if !m.confirmCredentialSuccess(ctx, httpClient, endpoint, cred, baseline, cr) {
			continue
		}

		rawReq := m.buildCredentialRequest(ctx, endpoint, cred.username, cred.password)
		results = append(results, &output.ResultEvent{
			URL:              ctx.Target(),
			Request:          string(rawReq),
			Response:         cr.raw,
			FuzzingParameter: endpoint.usernameField,
			ExtractedResults: []string{
				fmt.Sprintf("Username: %s", cred.username),
				fmt.Sprintf("Password: %s", cred.password),
			},
			Info: output.Info{
				Description: fmt.Sprintf("Default credentials found: %s/%s", cred.username, cred.password),
			},
		})
		return results, nil // Stop on first confirmed success
	}

	return results, nil
}

// confirmCredentialSuccess re-verifies a candidate "success" before it is
// reported: (1) re-sending the same credentials must reproduce the success
// verdict (deterministic, not a transient), and (2) the candidate response must
// be materially distinct from a fresh random-invalid control (so login-page
// variance that merely differs from the original baseline is not mistaken for
// authentication).
func (m *Module) confirmCredentialSuccess(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	endpoint *loginEndpoint,
	cred credentialPair,
	baseline, candidate credentialResponse,
) bool {
	repeat, err := m.sendCredentials(ctx, httpClient, endpoint, cred.username, cred.password)
	if err != nil || repeat.blocked {
		return false
	}
	if !isLoginSuccess(repeat, baseline) {
		return false
	}

	control, err := m.sendCredentials(ctx, httpClient, endpoint,
		"vigolium-control-user-9d4b", "vigolium-control-pass-1e7c")
	if err != nil || control.blocked {
		return false
	}
	// The decisive check against the "same response for any credentials" class of
	// false positive (a captcha/error gate that rejects everything identically):
	// if the "successful" response is indistinguishable from a fresh
	// random-credential control — same status, same redirect target, similar body
	// — it is not authentication, it is the endpoint's uniform rejection.
	if responsesEquivalent(candidate, control) {
		return false
	}
	return true
}

// responsesEquivalent reports whether two login responses are effectively the
// same outcome: same status, same redirect target, and textually similar body.
// Comparison is body-only (see credentialResponse) plus the Location header,
// never the volatile full response string. Two uses: detecting an endpoint that
// returns the identical response regardless of the credentials supplied, and
// gating the failed-login baseline as stable (two invalid probes must agree).
func responsesEquivalent(a, b credentialResponse) bool {
	if a.statusCode != b.statusCode {
		return false
	}
	if !sameLocation(a.location, b.location) {
		return false
	}
	return modkit.BodiesSimilar(a.body, b.body)
}

// sendCredentials sends a login request with the given credentials and extracts response data.
func (m *Module) sendCredentials(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	endpoint *loginEndpoint,
	username, password string,
) (credentialResponse, error) {
	rawReq := m.buildCredentialRequest(ctx, endpoint, username, password)

	// rawReq is well-formed raw, so wrap directly instead of re-parsing on this hot path.
	fuzzedReq := httpmsg.NewRequestResponseRaw(rawReq, ctx.Service())

	// NoClustering: confirmCredentialSuccess re-sends the SAME credentials to prove the
	// success verdict reproduces (deterministic, not a one-off differential). The 500ms
	// request-cluster cache keys on raw request bytes, so a clustered re-send returns
	// the first response's cached copy and "reproduces" trivially — even for a transient
	// success (a false positive). Every credential send must be a genuine round-trip.
	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{NoRedirects: true, NoClustering: true})
	if err != nil {
		return credentialResponse{}, err
	}
	defer resp.Close()

	cr := credentialResponse{}
	if resp.Response() != nil {
		cr.statusCode = resp.Response().StatusCode
		cr.hasSetCookie = resp.Response().Header.Get("Set-Cookie") != ""
		cr.location = resp.Response().Header.Get("Location")
	}
	cr.body = resp.BodyString()
	cr.raw = resp.FullResponseString()

	// Flag only vendor-identified WAF/CDN edge blocks/challenges (Cloudflare,
	// Akamai, CloudFront, Incapsula — including 200-status challenge bodies), NOT a
	// plain application 401: a 401 is the *expected* failed-login baseline this
	// module is built around, so infra.IsBlockedResponse (which treats 401/403 as
	// blocked) is deliberately not used here.
	cr.blocked = modkit.IsEdgeBlockedResponse(httpmsg.NewHttpResponse([]byte(cr.raw)))

	return cr, nil
}

// buildCredentialRequest constructs the raw request with credentials.
func (m *Module) buildCredentialRequest(
	ctx *httpmsg.HttpRequestResponse,
	endpoint *loginEndpoint,
	username, password string,
) []byte {
	raw := ctx.Request().Raw()

	if endpoint.isJSON {
		// Parse existing JSON body, replace username and password fields
		body := ctx.Request().BodyToString()
		var jsonBody map[string]interface{}
		if err := json.Unmarshal([]byte(body), &jsonBody); err != nil {
			return raw
		}
		jsonBody[endpoint.usernameField] = username
		jsonBody[endpoint.passwordField] = password

		newBody, err := json.Marshal(jsonBody)
		if err != nil {
			return raw
		}

		modified, err := httpmsg.SetBodyString(raw, string(newBody))
		if err != nil {
			return raw
		}
		return modified
	}

	// Form-encoded: get existing params and replace username/password
	existingParams, err := httpmsg.GetBodyParametersMap(raw)
	if err != nil {
		existingParams = make(map[string]string)
	}

	existingParams[endpoint.usernameField] = username
	existingParams[endpoint.passwordField] = password

	modified, err := httpmsg.SetBodyParametersMap(raw, existingParams)
	if err != nil {
		return raw
	}
	return modified
}
