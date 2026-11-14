package rails_fingerprint

import (
	"strings"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
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
			modkit.PassiveScanScopeResponse,
		),
		ds: dedup.LazyDiskSet("rails_fingerprint"),
	}
	m.ModuleTags = ModuleTags
	return m
}

func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	if !ctx.HasResponse() {
		return nil, nil
	}

	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	host := urlx.Host
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	if diskSet != nil && diskSet.Contains(host) {
		return nil, nil
	}

	hdr := func(name string) string { return ctx.Response().Header(name) }
	body := ctx.Response().BodyToString()

	// Detection signals are split into strong (Rails-exclusive) and weak (generic
	// or shared with other frameworks). Rails is marked on any one strong signal,
	// or two corroborating weak signals — a single weak signal is too ambiguous
	// (the default-500 wording is a generic apology; the csrf-token meta tag is
	// shared with Laravel and others), so it would false-positive on its own.
	strong := 0
	weak := 0
	var extracted []string
	meta := map[string]any{
		"platform": "rails",
	}

	// Header signals: X-Request-Id + X-Runtime combination is a strong Rails indicator
	if hdr("X-Request-Id") != "" && hdr("X-Runtime") != "" {
		strong++
		extracted = append(extracted, "X-Request-Id: present")
		extracted = append(extracted, "X-Runtime: "+hdr("X-Runtime"))
	}

	// Server header signals (Ruby application servers)
	serverHdr := strings.ToLower(hdr("Server"))
	switch {
	case strings.Contains(serverHdr, "puma"):
		strong++
		extracted = append(extracted, "Server: Puma")
		meta["server"] = "puma"
	case strings.Contains(serverHdr, "unicorn"):
		strong++
		extracted = append(extracted, "Server: Unicorn")
		meta["server"] = "unicorn"
	case strings.Contains(serverHdr, "passenger"):
		strong++
		extracted = append(extracted, "Server: Passenger")
		meta["server"] = "passenger"
	}

	// Cookie signals: Rails session cookies typically named _<app>_session
	for _, h := range ctx.Response().Headers() {
		if !strings.EqualFold(h.Name, "Set-Cookie") {
			continue
		}
		cookieLower := strings.ToLower(h.Value)
		if strings.Contains(cookieLower, "_session=") && !strings.Contains(cookieLower, "asp") {
			strong++
			// Extract cookie name
			parts := strings.SplitN(h.Value, "=", 2)
			if len(parts) > 0 {
				extracted = append(extracted, "Cookie: "+strings.TrimSpace(parts[0]))
			}
		}
	}

	// Body signals (only check HTML responses)
	ct := strings.ToLower(hdr("Content-Type"))
	if strings.Contains(ct, "text/html") {
		// Default Rails 404 page (distinctive wording)
		if strings.Contains(body, "The page you were looking for doesn't exist") {
			strong++
			extracted = append(extracted, "Body: Default Rails 404 page")
		}
		// Turbo/Turbolinks (Rails Hotwire markers)
		if strings.Contains(body, "data-turbo-track") || strings.Contains(body, "data-turbolinks-track") {
			strong++
			extracted = append(extracted, "Body: Turbo/Turbolinks")
			meta["turbo"] = true
		}
		// Action Cable meta tag (Rails-specific)
		if strings.Contains(body, `name="action-cable-url"`) {
			strong++
			extracted = append(extracted, "Body: Action Cable meta tag")
			meta["actionCable"] = true
		}
		// Weak: the default Rails 500 wording is a generic apology phrase.
		if strings.Contains(body, "We're sorry, but something went wrong") {
			weak++
			extracted = append(extracted, "Body: Default Rails 500 page")
		}
		// Weak: the csrf-token meta tag is also used by Laravel and others.
		if strings.Contains(body, `name="csrf-token"`) || strings.Contains(body, `name="csrf-param"`) {
			weak++
			extracted = append(extracted, "Body: Rails CSRF meta tag")
		}
	}

	if strong == 0 && weak < 2 {
		return nil, nil
	}

	desc := "Ruby on Rails application detected"
	if server, ok := meta["server"]; ok {
		desc += " running on " + server.(string)
	}

	scanCtx.MarkTech(host, "rails")
	scanCtx.MarkTech(host, "ruby")

	// Claim the host only now that it matched (MISS-19): a host whose
	// first response showed nothing stays open for later responses.
	if diskSet != nil && !diskSet.ClaimOnMatch(host) {
		return nil, nil
	}
	return []*output.ResultEvent{
		{
			ModuleID:         ModuleID,
			Host:             host,
			URL:              urlx.String(),
			Matched:          urlx.String(),
			ExtractedResults: extracted,
			Info: output.Info{
				Name:        "Ruby on Rails Application Detected",
				Description: desc,
				Severity:    severity.Info,
				Confidence:  severity.Certain,
				Tags:        []string{"rails", "ruby", "fingerprint"},
			},
			Metadata: meta,
		},
	}, nil
}
