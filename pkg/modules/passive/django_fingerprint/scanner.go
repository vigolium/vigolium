package django_fingerprint

import (
	"strings"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// Module implements the Django Fingerprint passive scanner.
type Module struct {
	modkit.BasePassiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new Django Fingerprint module.
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
		ds: dedup.LazyDiskSet("django_fingerprint"),
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
	if diskSet != nil && diskSet.IsSeen(host) {
		return nil, nil
	}

	body := ctx.Response().BodyToString()

	var extracted []string
	meta := map[string]any{
		"platform": "django",
	}

	// Signal tracking
	hasCsrfToken := false
	hasSessionId := false
	hasCsrfMiddleware := false
	hasDjangoBody := false
	hasXFrameDeny := false
	hasDjangoError := false

	// Signal 1: Set-Cookie contains csrftoken=
	for _, h := range ctx.Response().Headers() {
		if !strings.EqualFold(h.Name, "Set-Cookie") {
			continue
		}
		cookieLower := strings.ToLower(h.Value)
		if strings.HasPrefix(cookieLower, "csrftoken=") {
			hasCsrfToken = true
			extracted = append(extracted, "Cookie: csrftoken")
		}
		// Signal 2: Set-Cookie contains sessionid=
		if strings.HasPrefix(cookieLower, "sessionid=") {
			hasSessionId = true
			extracted = append(extracted, "Cookie: sessionid")
		}
	}

	// Signal 3: Response body contains "csrfmiddlewaretoken"
	if strings.Contains(body, "csrfmiddlewaretoken") {
		hasCsrfMiddleware = true
		extracted = append(extracted, "Body: csrfmiddlewaretoken hidden field")
	}

	// Signal 4: Response body contains "django" or "Django" in admin/error contexts
	bodyLower := strings.ToLower(body)
	if strings.Contains(body, "Django administration") ||
		strings.Contains(body, "django-admin") ||
		strings.Contains(bodyLower, "powered by django") {
		hasDjangoBody = true
		extracted = append(extracted, "Body: Django reference detected")
	}

	// Signal 5: X-Frame-Options: DENY (weak signal)
	xfo := ctx.Response().Header("X-Frame-Options")
	if strings.EqualFold(xfo, "DENY") {
		hasXFrameDeny = true
	}

	// Signal 6: Django-specific error patterns
	if strings.Contains(body, "ImproperlyConfigured") ||
		strings.Contains(body, "OperationalError at /") {
		hasDjangoError = true
		extracted = append(extracted, "Body: Django error pattern detected")
		meta["hasDebugError"] = true
	}

	// Count independent signal categories
	signalCount := 0
	if hasCsrfToken {
		signalCount++
	}
	if hasSessionId {
		signalCount++
	}
	if hasCsrfMiddleware {
		signalCount++
	}
	if hasDjangoBody {
		signalCount++
	}
	if hasDjangoError {
		signalCount++
	}

	// X-Frame-Options: DENY is weak — only count if another signal is present
	if hasXFrameDeny && signalCount > 0 {
		signalCount++
		extracted = append(extracted, "Header: X-Frame-Options: DENY (Django default)")
	}

	// Require 2+ signals to report
	if signalCount < 2 {
		return nil, nil
	}

	desc := "Django application detected"
	if _, ok := meta["hasDebugError"]; ok {
		desc += " with debug error page exposed"
	}

	scanCtx.MarkTech(host, "django")

	return []*output.ResultEvent{
		{
			ModuleID:         ModuleID,
			Host:             host,
			URL:              urlx.String(),
			Matched:          urlx.String(),
			ExtractedResults: extracted,
			Info: output.Info{
				Name:        "Django Application Detected",
				Description: desc,
				Severity:    severity.Info,
				Confidence:  severity.Certain,
				Tags:        []string{"python", "django", "fingerprint"},
				Reference:   []string{"https://www.djangoproject.com/"},
			},
			Metadata: meta,
		},
	}, nil
}
