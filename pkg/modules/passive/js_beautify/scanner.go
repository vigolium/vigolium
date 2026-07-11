// Package js_beautify implements a passive module that unminifies and unpacks
// first-party JavaScript (React/Next/Vue SPA bundles) into readable source using
// the embedded jstangle tool (webcrack, no eval-based deobfuscation).
//
// For JavaScript responses the raw stored response remains immutable. The
// beautified, module-annotated document is persisted as a content-addressed
// companion artifact and linked to the record. Inline <script> code in HTML
// pages is beautified into the finding evidence. Known third-party vendor
// assets (analytics, captcha, chat/social/payment SDKs, CDN libraries) and
// scripts that are neither minified nor bundled are skipped.
package js_beautify

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/deparos/jstangle"
	"github.com/vigolium/vigolium/pkg/deparos/jsvendor"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/utils"
	"go.uber.org/zap"
)

// beautifyErrWarnOnce ensures a persistent jstangle failure (e.g. a stale
// embedded binary whose capability handshake does not advertise the "beautify"
// analysis profile) is surfaced once per process rather than silently swallowed
// into a no-op on every JS response.
var beautifyErrWarnOnce sync.Once

// Module implements the passive JavaScript beautifier.
type Module struct {
	modkit.BasePassiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new JavaScript Beautifier module.
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
		ds: dedup.LazyDiskSet("js_beautify"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ---- shared jstangle service ----

var (
	scannerOnce   sync.Once
	sharedScanner *jstangle.Service
)

// getScanner lazily builds the shared jstangle scanner. Returns nil if the
// embedded binary is unavailable (unsupported platform / LFS pointer), in which
// case the module cleanly no-ops.
func getScanner() *jstangle.Service {
	scannerOnce.Do(func() {
		if service, err := jstangle.DefaultService(); err == nil {
			sharedScanner = service
		}
	})
	return sharedScanner
}

// bundleMarkers identifies runtime shapes that make a script worth unpacking
// even if it isn't obviously minified.
var bundleMarkers = regexp.MustCompile(`__webpack_require__|webpackChunk|webpackJsonp|self\.__next_f|System\.register|__esModule|Object\.defineProperty\(exports`)

const (
	minWorthLen        = 500
	minifiedAvgLine    = 200
	maxEvidencePaths   = 50
	maxEvidenceSnippet = 4000
)

// worthBeautifying is a cheap Go-side pre-gate mirroring the jstangle tool's own
// heuristic, so we avoid spawning a subprocess for tiny or already-readable
// scripts. The tool re-checks and returns no beautified record if it disagrees.
func worthBeautifying(code string) bool {
	if len(code) < minWorthLen {
		return false
	}
	if bundleMarkers.MatchString(code) {
		return true
	}
	newlines := strings.Count(code, "\n")
	avgLine := len(code) / (newlines + 1)
	return avgLine >= minifiedAvgLine
}

// scriptTagRe matches <script ...>...</script> blocks (inline scripts).
var scriptTagRe = regexp.MustCompile(`(?is)<script([^>]*)>(.*?)</script>`)

// srcAttrRe / typeAttrRe pick out attributes we use to skip non-inline or
// non-JavaScript <script> tags.
var (
	srcAttrRe  = regexp.MustCompile(`(?is)\bsrc\s*=`)
	typeAttrRe = regexp.MustCompile(`(?is)\btype\s*=\s*["']?([^"'\s>]+)`)
)

// extractInlineScripts concatenates the JavaScript of inline <script> blocks in
// an HTML document (skipping external src= scripts and non-JS types such as
// application/json or text/x-template).
func extractInlineScripts(html string) string {
	var b strings.Builder
	for _, mm := range scriptTagRe.FindAllStringSubmatch(html, -1) {
		attrs, inner := mm[1], mm[2]
		if srcAttrRe.MatchString(attrs) {
			continue // external script — handled as its own JS record
		}
		if t := typeAttrRe.FindStringSubmatch(attrs); t != nil {
			typ := strings.ToLower(t[1])
			if typ != "text/javascript" && typ != "application/javascript" &&
				typ != "module" && typ != "text/ecmascript" && typ != "application/ecmascript" {
				continue // JSON, templates, importmap, etc.
			}
		}
		if strings.TrimSpace(inner) == "" {
			continue
		}
		// Skip inline vendor snippets (GA/GTM, captcha, consent managers, ...) so
		// only first-party inline app code is beautified.
		if jsvendor.IsVendorScriptContent(inner) {
			continue
		}
		b.WriteString(inner)
		b.WriteString("\n;\n")
	}
	return b.String()
}

// CanProcess accepts JS responses (by content-type or URL extension) and HTML
// responses (for inline scripts), with a non-empty body.
func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	if ctx == nil || ctx.Response() == nil {
		return false
	}
	if len(ctx.Response().Body()) == 0 {
		return false
	}
	ct := strings.ToLower(ctx.Response().Header("Content-Type"))
	if modkit.IsJSOrTSContentType(ct) || strings.Contains(ct, "text/html") {
		return true
	}
	if u, err := ctx.URL(); err == nil {
		if modkit.HasJSExtension(strings.ToLower(u.Path)) {
			return true
		}
	}
	return false
}

// ScanPerRequest satisfies the legacy PassiveModule interface by delegating to
// the context-aware path with a background context.
func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	return m.ScanPerRequestContext(context.Background(), ctx, scanCtx)
}

// ScanPerHost is a no-op; this module works per request.
func (m *Module) ScanPerHost(_ *httpmsg.HttpRequestResponse, _ *modkit.ScanContext) ([]*output.ResultEvent, error) {
	return nil, nil
}

// ScanPerHostContext is a no-op; this module works per request.
func (m *Module) ScanPerHostContext(_ context.Context, _ *httpmsg.HttpRequestResponse, _ *modkit.ScanContext) ([]*output.ResultEvent, error) {
	return nil, nil
}

// ScanPerRequestContext beautifies a JS response into an immutable companion
// artifact or an HTML page's inline scripts into evidence, cancellable via ctx.
func (m *Module) ScanPerRequestContext(ctx context.Context, item *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	if item == nil || !item.HasResponse() {
		return nil, nil
	}
	urlx, err := item.URL()
	if err != nil {
		return nil, nil
	}
	resp := item.Response()
	ct := strings.ToLower(resp.Header("Content-Type"))
	pathLower := strings.ToLower(urlx.Path)

	isJS := modkit.IsJSOrTSContentType(ct) || modkit.HasJSExtension(pathLower)
	isHTML := strings.Contains(ct, "text/html")
	if !isJS && !isHTML {
		return nil, nil
	}

	// Is the scan actually targeting this host? A known-vendor host/script is only
	// treated as third-party (and skipped) when it is NOT the target — so
	// pentesting the vendor itself (Sentry, PostHog, DataDome, ...) still
	// beautifies its own scripts.
	isTarget := scanCtx.IsScanTarget(urlx.Host)

	// Cheap URL-based vendor gates for JS (the HTML page itself is the first-party
	// target; its inline scripts are filtered per-block in extractInlineScripts).
	if isJS {
		// Shared vendor infra — CDN library files and reCAPTCHA/Cloudflare/Akamai
		// bot-management paths — is always third-party, regardless of target.
		if jsvendor.IsLibraryFile(urlx.Path) || jsvendor.IsVendorPath(urlx.Path) {
			return nil, nil
		}
		// A known-vendor HOST is third-party unless the scan targets that vendor.
		if !isTarget && jsvendor.IsVendorDomain(urlx.Host) {
			return nil, nil
		}
	}

	// Dedup by host+path before any body work: the decision is deterministic per
	// host+path, so a duplicate always reaches the same outcome — dedup-first
	// avoids re-scanning the body and re-spawning the subprocess.
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	if diskSet != nil && diskSet.IsSeen(utils.Sha1(urlx.Host+urlx.Path)) {
		return nil, nil
	}

	// Pull the JavaScript to beautify. For a JS response the subprocess reads the
	// raw body directly (zero-copy slice); the string form (memoized, shared with
	// other passive modules) is only for the cheap gates. For HTML the input is the
	// concatenated inline scripts.
	var jsInput string
	var scanBytes []byte
	if isJS {
		jsInput = resp.BodyToString()
		scanBytes = resp.Body()
	} else {
		jsInput = extractInlineScripts(resp.BodyToString())
		if strings.TrimSpace(jsInput) == "" {
			return nil, nil
		}
		scanBytes = []byte(jsInput)
	}

	// Only spend a subprocess on minified / bundled code (cheapest gate first).
	if !worthBeautifying(jsInput) {
		return nil, nil
	}
	// Vendor runtime served from the target's own domain or under an obfuscated
	// filename, which the URL gate can't catch. After worthBeautifying so the
	// full-body signature scan runs only on scripts we'd actually beautify.
	if isJS && !isTarget && jsvendor.IsVendorScriptContent(jsInput) {
		return nil, nil
	}

	scanner := getScanner()
	if scanner == nil {
		return nil, nil // binary unavailable — no-op
	}

	res, scanErr := scanner.ScanWithOptions(ctx, scanBytes, jstangle.ScanOptions{
		Profile: jstangle.ProfileBeautify, SourceURL: urlx.String(),
		Filename: filepath.Base(urlx.Path), MediaType: ct,
	})
	if scanErr != nil {
		// Don't fail the scan on a beautify error, but surface it once with an
		// accurate diagnostic. Beautification is requested via the "beautify"
		// analysis profile (a field in the framed worker request), not a CLI flag;
		// a stale embedded binary that lacks it reports so in its capability
		// handshake and Analyze returns ErrUnsupportedProfile.
		if ctx.Err() == nil {
			beautifyErrWarnOnce.Do(func() {
				if errors.Is(scanErr, jstangle.ErrUnsupportedProfile) {
					zap.L().Warn("js_beautify: embedded jstangle binary does not advertise the \"beautify\" profile; JS beautification disabled for this run — update the embedded jstangle binary",
						zap.Error(scanErr))
				} else {
					zap.L().Warn("js_beautify: jstangle beautify failed; JS beautification disabled for this run",
						zap.Error(scanErr))
				}
			})
		}
		return nil, nil
	}
	if res == nil || !res.HasBeautified() {
		return nil, nil
	}
	b := res.Beautified

	// Resolve the stored record UUID for artifact linkage / tagging.
	var uuid string
	if scanCtx != nil && scanCtx.RequestUUIDResolver != nil {
		uuid = scanCtx.RequestUUIDResolver.ResolveRequestUUID(item.Request().ID())
	}

	artifactStored := false
	if uuid != "" {
		if isJS {
			if writer := scanCtx.DerivedArtifactWriterOrNil(); writer != nil {
				content := []byte(b.Content)
				digest := sha256.Sum256(content)
				filename := filepath.Base(urlx.Path)
				if filename == "." || filename == "/" || filename == "" {
					filename = "bundle.js"
				}
				filename += ".beautified.js"
				err := writer.StoreDerivedArtifact(ctx, &modkit.DerivedArtifact{
					RecordUUID: uuid,
					Kind:       "beautified-source",
					Filename:   filename,
					MediaType:  "application/javascript",
					SHA256:     fmt.Sprintf("%x", digest),
					Content:    content,
					Metadata: map[string]any{
						"format":      b.Format,
						"moduleCount": b.ModuleCount,
						"modulePaths": b.ModulePaths,
					},
				})
				if err == nil {
					artifactStored = true
					m.tag(scanCtx, uuid, "js-beautified-artifact", "js-format:"+b.Format)
				} else {
					zap.L().Warn("js_beautify: failed to persist immutable artifact", zap.String("record_uuid", uuid), zap.Error(err))
				}
			}
		} else {
			m.tag(scanCtx, uuid, "js-inline-beautified")
		}
	}

	return []*output.ResultEvent{m.buildFinding(urlx.String(), urlx.Host, b, !isJS, artifactStored)}, nil
}

// tag appends record remarks via the annotator when one is wired.
func (m *Module) tag(scanCtx *modkit.ScanContext, uuid string, tags ...string) {
	if scanCtx == nil || scanCtx.RemarksAnnotator == nil || uuid == "" {
		return
	}
	_ = scanCtx.RemarksAnnotator.AppendRemarks(context.Background(), map[string][]string{uuid: tags})
}

// buildFinding constructs the info-severity finding describing the beautification.
func (m *Module) buildFinding(url, host string, b *jstangle.BeautifiedCode, inline, artifactStored bool) *output.ResultEvent {
	// Copy so the truncation below never mutates b.ModulePaths.
	extracted := append([]string(nil), b.ModulePaths...)
	if len(extracted) > maxEvidencePaths {
		extracted = append(extracted[:maxEvidencePaths], fmt.Sprintf("… +%d more modules", len(b.ModulePaths)-maxEvidencePaths))
	}

	var desc strings.Builder
	if b.Format != "none" && b.ModuleCount > 0 {
		fmt.Fprintf(&desc, "Unpacked a %s bundle into %d module(s) and unminified them.", b.Format, b.ModuleCount)
	} else {
		desc.WriteString("Unminified a minified script into readable source.")
	}
	switch {
	case inline:
		desc.WriteString(" Inline <script> code was beautified into the evidence below; the HTML page body was not modified.")
	case artifactStored:
		desc.WriteString(" The raw response was preserved and the full beautified document was stored as an immutable companion artifact.")
	default:
		desc.WriteString(" The raw response was preserved; a preview is available in evidence (no artifact writer was configured).")
	}

	ev := []string{modkit.Truncate(b.Content, maxEvidenceSnippet)}

	return &output.ResultEvent{
		ModuleID:           ModuleID,
		Type:               "http",
		Host:               host,
		URL:                url,
		Matched:            url,
		MatcherStatus:      true,
		ExtractedResults:   extracted,
		AdditionalEvidence: ev,
		Info: output.Info{
			Name:        fmt.Sprintf("Beautified JavaScript (%s, %d modules)", b.Format, b.ModuleCount),
			Description: desc.String(),
			Severity:    ModuleSeverity,
			Confidence:  ModuleConfidence,
			Tags:        ModuleTags,
		},
		Metadata: map[string]any{
			"format":         b.Format,
			"moduleCount":    b.ModuleCount,
			"inline":         inline,
			"rewritten":      false,
			"rawPreserved":   true,
			"artifactStored": artifactStored,
			"contentBytes":   len(b.Content),
		},
	}
}
