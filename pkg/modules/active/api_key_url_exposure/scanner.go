package api_key_url_exposure

import (
	"fmt"
	"strings"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/utils"
)

var authHeaders = []struct {
	header    string
	urlParams []string
}{
	{"Authorization", []string{"authorization", "access_token", "token"}},
	{"X-API-Key", []string{"api_key", "apikey"}},
	{"Api-Key", []string{"api_key", "apikey"}},
	{"X-Auth-Token", []string{"auth_token", "token"}},
	{"X-Access-Token", []string{"access_token", "token"}},
}

var credentialHeaders = []string{
	"Authorization", "Proxy-Authorization", "Cookie", "X-API-Key", "Api-Key",
	"X-Api-Token", "X-Auth-Token", "X-Access-Token", "X-Session-Token",
}

type probeObservation struct {
	status   int
	body     string
	response string
	ok       bool
}

// Module implements the API Key in URL active scanner.
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
		ds: dedup.LazyDiskSet("api_key_url_exposure"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerRequest proves credential-location handling with four controls on an
// isolated client: no credential, invalid credential, valid credential, and a
// valid replay. It only probes idempotent GET requests. A single 2xx response is
// insufficient, and the result remains a candidate because downstream logging
// or referrer disclosure is not directly observed.
func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, httpClient *http.Requester, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	urlx, err := ctx.URL()
	if err != nil || ctx.Request() == nil || !strings.EqualFold(ctx.Request().Method(), "GET") {
		return nil, nil
	}
	if utils.IsMediaAndJSURL(urlx.Path) || ctx.Response() == nil || ctx.Response().StatusCode() < 200 || ctx.Response().StatusCode() >= 300 || len(strings.TrimSpace(ctx.Response().BodyToString())) < 2 {
		return nil, nil
	}

	diskSet := m.ds.Get(scanCtx.DedupMgr())
	hash := utils.Sha1(fmt.Sprintf("%s%s", urlx.Host, urlx.Path))
	if diskSet != nil && diskSet.IsSeen(hash) {
		return nil, nil
	}

	for _, headerSpec := range authHeaders {
		headerValue, headerErr := httpmsg.GetHeaderValue(ctx.Request().Raw(), headerSpec.header)
		if headerErr != nil || !credentialValueLooksReal(headerValue) {
			continue
		}
		paramName := headerSpec.urlParams[0]
		if requestAlreadyHasCredentialParam(urlx.RawQuery, headerSpec.urlParams) {
			return nil, nil
		}

		cleanRaw, cleanErr := stripCredentialHeaders(ctx.Request().Raw())
		if cleanErr != nil {
			return nil, nil
		}
		validRaw, appendErr := httpmsg.AppendURLParameter(cleanRaw, paramName, headerValue)
		if appendErr != nil {
			return nil, nil
		}
		invalidValue := mutateCredential(headerValue)
		invalidRaw, appendErr := httpmsg.AppendURLParameter(cleanRaw, paramName, invalidValue)
		if appendErr != nil {
			return nil, nil
		}

		anonymousClient, cloneErr := httpClient.CloneWithoutCredentials()
		if cloneErr != nil {
			return nil, nil
		}

		control := fetch(anonymousClient, ctx.Service(), cleanRaw)
		invalid := fetch(anonymousClient, ctx.Service(), invalidRaw)
		validFirst := fetch(anonymousClient, ctx.Service(), validRaw)
		validReplay := fetch(anonymousClient, ctx.Service(), validRaw)
		if !control.ok || !invalid.ok || !validFirst.ok || !validReplay.ok {
			return nil, nil
		}

		originalSig := modkit.NewResponseSignature(ctx.Response().StatusCode(), ctx.Response().BodyToString(), headerValue)
		validFirstSig := modkit.NewResponseSignature(validFirst.status, validFirst.body, headerValue)
		validReplaySig := modkit.NewResponseSignature(validReplay.status, validReplay.body, headerValue)
		controlSig := modkit.NewResponseSignature(control.status, control.body, invalidValue)
		invalidSig := modkit.NewResponseSignature(invalid.status, invalid.body, invalidValue)

		if validFirst.status < 200 || validFirst.status >= 300 || validReplay.status < 200 || validReplay.status >= 300 ||
			!modkit.RatioSimilar(validFirstSig, validReplaySig) ||
			!modkit.RatioSimilar(originalSig, validFirstSig) ||
			!modkit.RatioSimilar(controlSig, invalidSig) ||
			modkit.RatioSimilar(controlSig, validFirstSig) || modkit.RatioSimilar(invalidSig, validFirstSig) {
			return nil, nil
		}

		return []*output.ResultEvent{{
			ModuleID:      ModuleID,
			RecordKind:    output.RecordKindCandidate,
			EvidenceGrade: output.EvidenceGradeDifferential,
			Host:          urlx.Host,
			URL:           urlx.String(),
			Matched:       urlx.String(),
			Request:       string(validRaw),
			Response:      validFirst.response,
			ExtractedResults: []string{
				fmt.Sprintf("credential_header=%s url_parameter=%s", headerSpec.header, paramName),
				fmt.Sprintf("control_status=%d invalid_status=%d valid_status=%d replay_status=%d", control.status, invalid.status, validFirst.status, validReplay.status),
				"valid URL response matched the authenticated baseline and replay; missing and bit-flipped credentials matched each other",
			},
			Info: output.Info{
				Name:        fmt.Sprintf("Credential Accepted from URL Parameter (%s)", headerSpec.header),
				Description: fmt.Sprintf("An isolated client reproduced the authenticated response twice with the %s credential in ?%s=, while no-credential and bit-flipped controls were rejected. This confirms URL-based credential transport, but not that production logs, history, or referrers actually disclosed the credential.", headerSpec.header, paramName),
				Severity:    ModuleSeverity,
				Confidence:  ModuleConfidence,
				Tags:        ModuleTags,
			},
			Metadata: map[string]any{
				"credential_header":   headerSpec.header,
				"url_parameter":       paramName,
				"replay_count":        2,
				"disclosure_observed": false,
			},
		}}, nil
	}
	return nil, nil
}

func fetch(client *http.Requester, service *httpmsg.Service, raw []byte) probeObservation {
	req, err := httpmsg.ParseRawRequest(string(raw))
	if err != nil {
		return probeObservation{}
	}
	if service != nil {
		req = req.WithService(service)
	}
	resp, _, err := client.Execute(req, http.Options{NoRedirects: true, NoClustering: true})
	if err != nil {
		if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
			return probeObservation{}
		}
		return probeObservation{}
	}
	defer resp.Close()
	if resp.Response() == nil {
		return probeObservation{}
	}
	return probeObservation{status: resp.Response().StatusCode, body: resp.Body().String(), response: resp.FullResponseString(), ok: true}
}

func stripCredentialHeaders(raw []byte) ([]byte, error) {
	clean := append([]byte(nil), raw...)
	var err error
	for _, header := range credentialHeaders {
		clean, err = httpmsg.RemoveHeader(clean, header)
		if err != nil {
			return nil, err
		}
	}
	return clean, nil
}

func requestAlreadyHasCredentialParam(rawQuery string, names []string) bool {
	queryLower := strings.ToLower(rawQuery)
	for _, name := range names {
		if strings.Contains("&"+queryLower+"&", "&"+strings.ToLower(name)+"=") {
			return true
		}
	}
	return false
}

func credentialValueLooksReal(value string) bool {
	value = strings.TrimSpace(value)
	if len(value) < 8 {
		return false
	}
	parts := strings.Fields(value)
	if len(parts) == 1 {
		return !modkit.IsPlaceholderValue(parts[0])
	}
	return len(parts[len(parts)-1]) >= 6 && !modkit.IsPlaceholderValue(parts[len(parts)-1])
}

func mutateCredential(value string) string {
	if value == "" {
		return "invalid-control"
	}
	last := value[len(value)-1]
	replacement := byte('A')
	if last == 'A' {
		replacement = 'B'
	}
	return value[:len(value)-1] + string(replacement)
}
