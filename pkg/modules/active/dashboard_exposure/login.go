package dashboard_exposure

import (
	"encoding/base64"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra/dashboardsig"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/vigolium/vigolium/pkg/utils"
)

// maxLoginRequests caps the HTTP requests one product's default-login probe may
// issue (negative control + a handful of documented credential pairs), so the
// check stays bounded even if a product accrues many credential pairs.
const maxLoginRequests = 10

// tryDefaultLogin attempts a product's documented default credentials against the
// confirmed base, once per (host, product). It first runs a negative control — a
// random credential pair MUST be rejected by the success matcher — so a login
// endpoint that "succeeds" on anything (or a catch-all) cannot produce a false
// positive. Returns a Critical finding only when a documented pair authenticates
// and the negative control did not. Decrements the shared per-host budget.
func (m *Module) tryDefaultLogin(
	client *http.Requester, rawHTTP []byte, svc *httpmsg.Service,
	baseURL, prefix, host string, p *dashboardsig.Product,
	loginDS *dedup.DiskSet, budget *int,
) *output.ResultEvent {
	lp := p.Login
	if lp == nil || len(lp.Creds) == 0 || len(lp.Paths) == 0 {
		return nil
	}
	// Once per (host, product) across the whole scan.
	if loginDS != nil && loginDS.IsSeen("login\x00"+host+"\x00"+p.ID) {
		return nil
	}

	spent := 0
	step := func() bool { // false when the per-host or per-product budget is exhausted
		if *budget <= 0 || spent >= maxLoginRequests {
			return false
		}
		*budget--
		spent++
		return true
	}

	// Negative control: a random pair must NOT satisfy the success matcher.
	if !step() {
		return nil
	}
	bogusUser := "vig-" + utils.RandomString(8)
	bogusPass := utils.RandomString(16)
	if neg := m.attemptLogin(client, rawHTTP, svc, prefix, lp, lp.Paths[0], bogusUser, bogusPass); neg != nil &&
		lp.Success.Match(neg.status, neg.get, neg.body, neg.bodyLower) {
		return nil // non-discriminating endpoint/matcher — abort to avoid a false positive
	}

	for _, cred := range lp.Creds {
		for _, path := range lp.Paths {
			if !step() {
				return nil
			}
			pr := m.attemptLogin(client, rawHTTP, svc, prefix, lp, path, cred[0], cred[1])
			if pr == nil {
				continue
			}
			if lp.Success.Match(pr.status, pr.get, pr.body, pr.bodyLower) {
				return buildLoginResult(p, host, baseURL+prefix+path, cred)
			}
		}
	}
	return nil
}

// attemptLogin builds and sends a single login request (one credential pair to
// one path) derived from rawHTTP, and returns the response with all header values
// preserved (Set-Cookie joined). Redirects are not followed and the cluster cache
// is bypassed so each attempt is a genuine, immediate observation.
func (m *Module) attemptLogin(
	client *http.Requester, rawHTTP []byte, svc *httpmsg.Service,
	prefix string, lp *dashboardsig.LoginProbe, path, user, pass string,
) *probeResp {
	raw, err := httpmsg.SetMethod(rawHTTP, lp.HTTPMethod())
	if err != nil {
		return nil
	}
	if raw, err = httpmsg.SetPath(raw, prefix+path); err != nil {
		return nil
	}

	if lp.BasicAuth {
		token := base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
		if raw, err = httpmsg.AddOrReplaceHeader(raw, "Authorization", "Basic "+token); err != nil {
			return nil
		}
	} else {
		body := strings.ReplaceAll(lp.Body, "{{user}}", user)
		body = strings.ReplaceAll(body, "{{pass}}", pass)
		if raw, err = httpmsg.SetBodyString(raw, body); err != nil {
			return nil
		}
		if lp.ContentType != "" {
			if raw, err = httpmsg.AddOrReplaceHeader(raw, "Content-Type", lp.ContentType); err != nil {
				return nil
			}
		}
	}

	req, err := httpmsg.ParseRawRequest(string(raw))
	if err != nil {
		return nil
	}
	req = req.WithService(svc)

	resp, _, err := client.Execute(req, http.Options{NoRedirects: true, NoClustering: true})
	if err != nil {
		return nil
	}
	defer resp.Close()
	// Join multi-valued headers (Set-Cookie can repeat) so a "contains" matcher
	// against the cookie jar sees every cookie, not just the first.
	return newProbeResp(resp, true)
}

// buildLoginResult reports a confirmed default-credential login as Critical. The
// working credentials are shown unredacted (they are a target-discovered secret,
// not an operator credential).
func buildLoginResult(p *dashboardsig.Product, host, url string, cred [2]string) *output.ResultEvent {
	creds := cred[0] + ":" + cred[1]
	tags := append([]string{"dashboard", "default-login", "default-creds", "credential"}, p.Tags...)
	desc := "The " + p.Name + " console at " + url + " accepted vendor-default credentials (" + creds + "). " +
		"This grants an attacker authenticated access — usually a direct path to data exfiltration, stored secrets, or remote code execution via job/plugin/tool definitions. " +
		"The login was confirmed against a negative control (a random credential pair was rejected), so it reflects a genuinely valid default account, not a permissive endpoint."
	return &output.ResultEvent{
		ModuleID:         ModuleID,
		Host:             host,
		URL:              url,
		Matched:          url,
		ExtractedResults: []string{"valid credentials: " + creds, "login endpoint: " + url},
		Info: output.Info{
			Name:        p.Name + " — Default Credentials Valid",
			Description: desc,
			Severity:    severity.Critical,
			Confidence:  severity.Certain,
			Tags:        tags,
			Reference:   p.References(),
		},
		Metadata: map[string]any{
			"product":       p.ID,
			"category":      p.Category,
			"default_login": true,
			"username":      cred[0],
			"password":      cred[1],
		},
	}
}
