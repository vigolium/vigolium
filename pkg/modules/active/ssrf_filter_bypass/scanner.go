package ssrf_filter_bypass

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

// oastPlaceholder is the sentinel "effective" host the confusion ladder is built
// around; it is replaced per payload with a freshly generated OAST hostname so
// each variant gets its own correlatable callback. It is an unresolvable
// .invalid name so a payload that is never substituted can never reach a real
// host.
const oastPlaceholder = "oast-effective.placeholder.invalid"

// Module implements the SSRF filter-bypass (URL parser confusion) active scanner.
type Module struct {
	modkit.BaseActiveModule
	ds  dedup.Lazy[dedup.DiskSet]
	rhm dedup.Lazy[dedup.RequestHashManager]
}

// New creates a new SSRF filter-bypass module.
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
		ds:  dedup.LazyDiskSet("ssrf_filter_bypass"),
		rhm: dedup.LazyDefaultRHM("ssrf_filter_bypass"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerInsertionPoint injects the URL-parser authority-confusion ladder into
// URL-like parameters, placing the target's own host as the trusted decoy and an
// OAST host as the effective fetch target. A callback confirms an allowlist
// bypass. Findings arrive asynchronously via OAST polling, so this returns nil.
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

	// Only test parameters that look like they accept URLs.
	if !infra.LooksLikeURLParam(ip.Name(), ip.BaseValue()) {
		return nil, nil
	}

	// Dedup by request hash + param (RHM) and by host+path+param (DiskSet).
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

	// The decoy is the target's own host — the value a same-origin/own-domain
	// allowlist is expected to trust.
	decoy := urlx.Hostname()
	if decoy == "" {
		return nil, nil
	}

	requestHash := ctx.Request().ID()

	for _, p := range infra.AuthorityConfusionPayloads(decoy, oastPlaceholder) {
		// Fresh OAST host per payload; the confusion label rides in the
		// injection-type for attribution when the callback fires.
		oastHost := oast.GenerateURL(urlx.String(), ip.Name(), "ssrf-confusion:"+p.Label, ModuleID, requestHash)
		if oastHost == "" {
			continue
		}
		payloadStr := strings.ReplaceAll(p.Value, oastPlaceholder, oastHost)

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
