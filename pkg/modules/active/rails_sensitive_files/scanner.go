package rails_sensitive_files

import (
	"crypto/sha256"
	"fmt"
	"math"
	"regexp"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/vigolium/vigolium/pkg/utils"
)

var masterKeyPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

// localSecretPattern matches the hex secret_key_base Rails writes to
// tmp/local_secret.txt (SecureRandom.hex → lowercase hex, 128 chars in modern
// Rails). It is anchored so a blank body, an HTML shell, or any non-hex
// catch-all placeholder fails — the same empty-200 false positive the /up
// health-check probe hits.
var localSecretPattern = regexp.MustCompile(`^[0-9a-f]{32,}$`)

type notFoundFingerprint struct {
	bodyHash string
	bodyLen  int
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
			modkit.ScanScopeRequest,
			modkit.AllInsertionPointTypes,
		),
		ds: dedup.LazyDiskSet("rails_sensitive_files"),
	}
	m.ModuleTags = ModuleTags
	return m
}

func (m *Module) IncludesBaseCanProcess() bool { return false }

func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	if ctx == nil || ctx.Request() == nil {
		return false
	}
	return ctx.Response() != nil
}

func (m *Module) ScanPerRequest(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	service := ctx.Service()
	if service == nil {
		return nil, nil
	}

	if !modkit.BeginHostProbeFor(scanCtx, httpClient, &m.ds, ctx) {
		return nil, nil
	}

	fp := m.fingerprint404(ctx, httpClient)

	var results []*output.ResultEvent
	for _, sf := range sensitiveFiles {
		if result := m.probeFile(ctx, httpClient, sf, fp); result != nil {
			results = append(results, result)
		}
	}
	return results, nil
}

func (m *Module) fingerprint404(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
) *notFoundFingerprint {
	randomPath := "/vigolium-rails-file-404-" + utils.RandomString(8)

	modifiedRaw, err := httpmsg.SetMethod(ctx.Request().Raw(), "GET")
	if err != nil {
		return nil
	}
	modifiedRaw, err = httpmsg.SetPath(modifiedRaw, randomPath)
	if err != nil {
		return nil
	}

	// BuildRequest/SetMethod/... produce well-formed raw, so wrap directly instead
	// of re-parsing on this hot path.
	fuzzedReq := httpmsg.NewRequestResponseRaw(modifiedRaw, ctx.Service())

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
	if err != nil {
		return nil
	}
	defer resp.Close()

	body := resp.Body().String()
	return &notFoundFingerprint{
		bodyHash: fmt.Sprintf("%x", sha256.Sum256([]byte(body))),
		bodyLen:  len(body),
	}
}

func (m *Module) probeFile(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	sf sensitiveFile,
	fp *notFoundFingerprint,
) *output.ResultEvent {
	modifiedRaw, err := httpmsg.SetMethod(ctx.Request().Raw(), "GET")
	if err != nil {
		return nil
	}
	modifiedRaw, err = httpmsg.SetPath(modifiedRaw, sf.path)
	if err != nil {
		return nil
	}

	// BuildRequest/SetMethod/... produce well-formed raw, so wrap directly instead
	// of re-parsing on this hot path.
	fuzzedReq := httpmsg.NewRequestResponseRaw(modifiedRaw, ctx.Service())

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
	if err != nil {
		return nil
	}
	defer resp.Close()

	if resp.Response() == nil {
		return nil
	}

	status := resp.Response().StatusCode
	if status == 404 || status == 500 || status == 502 || status == 503 || status == 403 || status == 401 {
		return nil
	}

	if status == 301 || status == 302 {
		location := resp.Response().Header.Get("Location")
		if strings.Contains(strings.ToLower(location), "login") {
			return nil
		}
	}

	body := resp.Body().String()

	if fp != nil {
		bodyHash := fmt.Sprintf("%x", sha256.Sum256([]byte(body)))
		if bodyHash == fp.bodyHash {
			return nil
		}
		if fp.bodyLen > 0 {
			ratio := math.Abs(float64(len(body)-fp.bodyLen)) / float64(fp.bodyLen)
			if ratio < 0.05 {
				return nil
			}
		}
	}

	// Catch-all / SPA shell guard: a themed app that returns the same shell for
	// any path is a false positive even when a weak marker appears in that shell.
	if modkit.ResemblesObservedPage(ctx, body) {
		return nil
	}

	// Content-type discipline (the decisive, zero-false-negative, truncation-proof
	// guard for this module): every file probed here is a Rails config / source /
	// log / data artifact — YAML (database.yml, secrets.yml), Ruby source
	// (puma.rb, schema.rb, seeds.rb), a plaintext log, an encrypted-credentials
	// blob, a hex key, or a SQLite binary — and NONE of them is ever served as an
	// HTML *document*. A universal catch-all / echo host that answers arbitrary
	// paths with its themed text/html shell would otherwise forge a match on a
	// weak reflected marker ("source"/"gem " for the Gemfile, "port"/"workers"
	// for puma.rb, "create"/"User" for seeds.rb) that survives in the response.
	// This class defeats the <html>/<!DOCTYPE> anti-markers and the 404
	// fingerprint under the gzip + bogus Content-Length:0 transport quirk, which
	// captures only a truncated TAIL fragment (no leading <!DOCTYPE); the
	// Content-Type header survives that truncation intact. A genuine Rails config
	// file never comes back as text/html, so this costs no true positives.
	if modkit.ClassifyContentType(resp.Response().Header.Get("Content-Type")) == modkit.ContentClassHTML {
		return nil
	}

	for _, anti := range sf.antiMarkers {
		if strings.Contains(body, anti) {
			return nil
		}
	}

	if status != 200 {
		return nil
	}

	var matchedMarkers []string

	if len(sf.markers) > 0 {
		matched := false
		for _, marker := range sf.markers {
			if strings.Contains(body, marker) {
				matched = true
				matchedMarkers = append(matchedMarkers, marker)
			}
		}
		if !matched {
			return nil
		}
	} else {
		// Files without markers need special validation
		switch sf.path {
		case "/config/master.key":
			trimmed := strings.TrimSpace(body)
			if !masterKeyPattern.MatchString(trimmed) {
				return nil
			}
			matchedMarkers = append(matchedMarkers, "master.key hex content")

		case "/config/credentials.yml.enc", "/config/credentials/production.yml.enc":
			contentType := resp.Response().Header.Get("Content-Type")
			if strings.Contains(strings.ToLower(contentType), "html") {
				return nil
			}
			contentLength := len(body)
			if contentLength <= 200 {
				return nil
			}
			matchedMarkers = append(matchedMarkers, "encrypted credentials blob")

		case "/tmp/local_secret.txt":
			// A real local secret is a long hex secret_key_base. A blank or
			// non-hex body (the catch-all / CDN empty-200 placeholder) carries no
			// signal: the upper bound alone let an empty body through and report a
			// secret leak. Require the hex token, bounded above to stay terse.
			trimmed := strings.TrimSpace(body)
			if len(trimmed) >= 256 || !localSecretPattern.MatchString(trimmed) {
				return nil
			}
			matchedMarkers = append(matchedMarkers, "local secret content")

		default:
			return nil
		}
	}

	urlx, _ := ctx.URL()
	targetURL := urlx.Scheme + "://" + urlx.Host + sf.path

	return &output.ResultEvent{
		URL:              targetURL,
		Matched:          targetURL,
		Request:          string(modifiedRaw),
		Response:         resp.FullResponseString(),
		ExtractedResults: matchedMarkers,
		Info: output.Info{
			Name:        fmt.Sprintf("Rails Sensitive File: %s", sf.name),
			Description: sf.desc,
			Severity:    modkit.CapSeverity(sf.sev, severity.Medium),
			Confidence:  severity.Tentative,
			Tags:        []string{"rails", "ruby", "sensitive-file", "information-disclosure"},
			Reference:   []string{"https://guides.rubyonrails.org/security.html"},
		},
	}
}
