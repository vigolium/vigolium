package xml_saml_security

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
	"go.uber.org/zap"
)

// targetParams - only scan these parameter names (case-insensitive)
var targetParams = []string{"samlrequest", "samlresponse"}

// checkConfig holds one XXE probe: a payload builder plus the injection-type
// label that the OAST poller folds into the confirmed finding.
type checkConfig struct {
	name          string
	injectionType string
	build         func(*XMLDocument, *DecodedSAML, string) (string, error)
}

// Module implements XML SAML security scanning.
type Module struct {
	modkit.BaseActiveModule
	rhm dedup.Lazy[dedup.RequestHashManager]
}

// New creates a new XML SAML Security scanner module.
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
			modkit.URLParamTypes|modkit.BodyParamTypes, // SAML params only in URL query or POST body
		),
		rhm: dedup.LazyDefaultRHM("xml_saml_security"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerInsertionPoint plants out-of-band (OAST) XXE probes into SAML XML.
//
// Confirmation is purely out-of-band: each probe declares an external DTD /
// external entity pointing at a unique OAST callback URL, and a finding is
// emitted ASYNCHRONOUSLY by the OAST poller only if the target's XML parser
// actually resolves it and calls back. There is no synchronous, response-shape
// based verdict — that heuristic produced false positives (it could not tell a
// parsed DTD from a silently stripped one), so the module no-ops without OAST.
func (m *Module) ScanPerInsertionPoint(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	// Filter: only process SAMLRequest/SAMLResponse params.
	if !isSAMLParam(strings.ToLower(ip.Name())) {
		return nil, nil
	}

	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	// Deduplication check
	rhm := m.rhm.Get(scanCtx.DedupMgr())
	if rhm != nil {
		paramType := fmt.Sprintf("%d", ip.Type())
		if !rhm.ShouldCheckInsertionPoint(urlx, ctx.Request(), ip.Name(), ip.BaseValue(), paramType) {
			return nil, nil
		}
	}

	// Decode and parse the XML carried by the SAML value.
	decoded, err := DecodeSAML(ip.BaseValue())
	if err != nil {
		zap.L().Debug("XMLSAMLSecurity: failed to decode SAML", zap.String("param", ip.Name()), zap.Error(err))
		return nil, nil
	}

	doc, err := ParseXML(decoded.XMLContent)
	if err != nil {
		zap.L().Debug("XMLSAMLSecurity: failed to parse XML", zap.String("param", ip.Name()), zap.Error(err))
		return nil, nil
	}

	// Signature-stripping leg (synchronous, no OAST needed): report when the SP
	// accepts an unsigned-but-valid assertion while rejecting a wrong-identity one.
	if res := m.scanSignatureBypass(ctx, ip, httpClient, decoded); res != nil {
		return []*output.ResultEvent{res}, nil
	}

	// Remaining checks are out-of-band XXE probes — without an OAST channel there
	// is no sound signal, so stop here rather than fall back to a heuristic.
	oast := scanCtx.OASTProv()
	if oast == nil || !oast.Enabled() {
		return nil, nil
	}

	// Don't inject external entities into a document that already carries a DOCTYPE.
	if doc.HasDoctype {
		zap.L().Debug("XMLSAMLSecurity: document already has DOCTYPE, skipping", zap.String("param", ip.Name()))
		return nil, nil
	}

	checks := []checkConfig{
		{name: "DOCTYPE", injectionType: "XXE (SAML external DTD)", build: InjectDOCTYPE},
		{name: "ENTITY", injectionType: "XXE (SAML external entity)", build: InjectENTITY},
	}

	requestHash := ctx.Request().ID()

	for _, check := range checks {
		// GenerateURL returns a unique OAST host (correlation baked into the
		// subdomain); wrap it as an http:// callback for the external reference.
		oastHost := oast.GenerateURL(urlx.String(), ip.Name(), check.injectionType, ModuleID, requestHash)
		if oastHost == "" {
			continue
		}
		systemURL := "http://" + oastHost

		payload, err := check.build(doc, decoded, systemURL)
		if err != nil {
			zap.L().Debug("XMLSAMLSecurity: payload generation failed",
				zap.String("check", check.name), zap.Error(err))
			continue
		}

		if err := m.sendPayload(ctx, ip, httpClient, payload); err != nil {
			if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
				return nil, nil
			}
			// Other send errors are non-fatal; try the next probe.
			continue
		}
	}

	// Findings arrive asynchronously via OAST polling callbacks.
	return nil, nil
}

// sendPayload injects payload into the SAML insertion point and fires the
// request. The response is irrelevant — confirmation is out-of-band — so the
// response chain is closed immediately.
func (m *Module) sendPayload(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	httpClient *http.Requester,
	payload string,
) error {
	// BuildRequest produces well-formed raw, so wrap directly instead
	// of re-parsing on this hot path.
	modifiedReq := httpmsg.NewRequestResponseRaw(ip.BuildRequest([]byte(payload)), ctx.Service())

	resp, _, err := httpClient.Execute(modifiedReq, http.Options{})
	if err != nil {
		return err
	}
	resp.Close()
	return nil
}

// isSAMLParam checks if the parameter name is a SAML parameter.
func isSAMLParam(name string) bool {
	name = strings.ToLower(name)
	for _, target := range targetParams {
		if name == target {
			return true
		}
	}
	return false
}
