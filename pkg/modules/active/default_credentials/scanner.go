package default_credentials

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/pkg/errors"
)

// credentialResponse holds extracted values from a login attempt response.
type credentialResponse struct {
	statusCode   int
	body         string
	hasSetCookie bool
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

	host := service.Host()

	// Dedup by host
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	if diskSet != nil && diskSet.IsSeen(host) {
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

	// Send baseline with invalid credentials
	baseline, err := m.sendCredentials(ctx, httpClient, endpoint,
		"vigolium-invalid-user-7a3f", "vigolium-invalid-pass-9b2e")
	if err != nil {
		return nil, err
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

		// Check for lockout
		if isLockout(cr.body) {
			return results, nil // Stop testing
		}

		if isLoginSuccess(cr.statusCode, cr.body, baseline.statusCode, len(baseline.body), cr.hasSetCookie) {
			rawReq := m.buildCredentialRequest(ctx, endpoint, cred.username, cred.password)
			results = append(results, &output.ResultEvent{
				URL:              ctx.Target(),
				Request:          string(rawReq),
				Response:         cr.body,
				FuzzingParameter: endpoint.usernameField,
				ExtractedResults: []string{
					fmt.Sprintf("Username: %s", cred.username),
					fmt.Sprintf("Password: %s", cred.password),
				},
				Info: output.Info{
					Description: fmt.Sprintf("Default credentials found: %s/%s", cred.username, cred.password),
				},
			})
			return results, nil // Stop on first success
		}
	}

	return results, nil
}

// sendCredentials sends a login request with the given credentials and extracts response data.
func (m *Module) sendCredentials(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	endpoint *loginEndpoint,
	username, password string,
) (credentialResponse, error) {
	rawReq := m.buildCredentialRequest(ctx, endpoint, username, password)

	fuzzedReq, err := httpmsg.ParseRawRequest(string(rawReq))
	if err != nil {
		return credentialResponse{}, err
	}
	fuzzedReq = fuzzedReq.WithService(ctx.Service())

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{NoRedirects: true})
	if err != nil {
		return credentialResponse{}, err
	}
	defer resp.Close()

	cr := credentialResponse{}
	if resp.Response() != nil {
		cr.statusCode = resp.Response().StatusCode
		cr.hasSetCookie = resp.Response().Header.Get("Set-Cookie") != ""
	}
	cr.body = resp.FullResponse().String()

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
