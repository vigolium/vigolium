package auth_headers_detect

import (
	"context"
	"fmt"
	"strings"

	"go.uber.org/zap"

	"github.com/pkg/errors"
	urlutil "github.com/projectdiscovery/utils/url"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/utils"
)

type Module struct {
	modkit.BasePassiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

func New() *Module {
	m := &Module{
		BasePassiveModule: modkit.NewBasePassiveModule(
			ModuleID,
			ModuleName,
			ModuleDesc,
			ModuleShort,
			ModuleConfirmation,
			ModuleSeverity,
			ModuleConfidence,
			modkit.ScanScopeRequest,
			modkit.PassiveScanScopeRequest,
		),
		ds: dedup.LazyDiskSet("passive_auth_headers_detect"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerRequest analyzes request headers for authorization tokens.
func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	var results []*output.ResultEvent
	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	if utils.IsMediaAndJSURL(urlx.Path) {
		return results, nil
	}

	authValue := ctx.Request().Header("Authorization")
	// Require an actual credential, not just a bare scheme keyword. JS clients
	// routinely emit "Authorization: Bearer" (or "Bearer null"/"Bearer undefined")
	// when no token exists — that carries nothing sensitive and is not a credential,
	// so flagging it High/Firm is a false positive.
	if !hasCredentialMaterial(authValue) {
		return results, nil
	}
	// Drop responses that came from a WAF/CDN/edge block (e.g. a CloudFront
	// "Request blocked" 403) rather than the application: the request never
	// reached an authenticated boundary, so recording one is a false positive.
	if modkit.IsEdgeBlockedResponse(ctx.Response()) {
		return results, nil
	}
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	hash := m.getHash(urlx, "Authorization", authValue)
	if diskSet != nil && diskSet.IsSeen(hash) {
		return results, nil
	}
	results = append(results, &output.ResultEvent{
		Host:             urlx.Host,
		URL:              urlx.String(),
		FuzzingParameter: "Authorization",
		Request:          string(ctx.Request().Raw()),
		ExtractedResults: []string{authValue},
	})

	// Annotate record with semantic tags
	if scanCtx.RemarksAnnotator != nil && scanCtx.RequestUUIDResolver != nil {
		uuid := scanCtx.RequestUUIDResolver.ResolveRequestUUID(ctx.Request().ID())
		if uuid != "" {
			tags := []string{"auth-endpoint"}
			lower := strings.ToLower(authValue)
			if strings.HasPrefix(lower, "bearer ") {
				tags = append(tags, "bearer-auth")
			} else if strings.HasPrefix(lower, "basic ") {
				tags = append(tags, "basic-auth")
			}
			if err := scanCtx.RemarksAnnotator.AppendRemarks(context.Background(), map[string][]string{uuid: tags}); err != nil {
				zap.L().Debug("auth_headers_detect: failed to annotate", zap.Error(err))
			}
		}
	}

	return results, nil
}

func (m *Module) getHash(urlx *urlutil.URL, name, value string) string {
	return utils.Sha1(fmt.Sprintf("%s%s%s", urlx.Host, name, value))
}

// authSchemes are HTTP authentication scheme keywords. A header that is only one
// of these words (e.g. "Bearer") carries no credential and must not be flagged.
var authSchemes = map[string]bool{
	"basic": true, "bearer": true, "digest": true, "negotiate": true,
	"ntlm": true, "oauth": true, "hoba": true, "mutual": true,
	"vapid": true, "token": true, "apikey": true, "key": true,
	"scram-sha-1": true, "scram-sha-256": true, "aws4-hmac-sha256": true,
}

// hasCredentialMaterial reports whether an Authorization header value carries an
// actual credential. It rejects the empty header, a bare scheme keyword with no
// token ("Bearer"), and JS placeholder values ("Bearer null", "undefined").
func hasCredentialMaterial(authValue string) bool {
	v := strings.TrimSpace(authValue)
	if v == "" {
		return false
	}
	fields := strings.Fields(v)
	if len(fields) == 1 {
		// A single token: a raw scheme-less credential (some APIs do this), unless
		// it is a bare scheme word or a placeholder.
		return !authSchemes[strings.ToLower(fields[0])] && !modkit.IsPlaceholderValue(fields[0])
	}
	// scheme + credential: the credential portion must be real. strings.Fields
	// already stripped surrounding whitespace, so the rejoin needs no trim.
	cred := strings.Join(fields[1:], " ")
	return cred != "" && !modkit.IsPlaceholderValue(cred)
}
