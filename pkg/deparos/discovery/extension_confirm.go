package discovery

import (
	"net/url"
	"strings"
	"sync"

	"github.com/vigolium/vigolium/pkg/deparos/config"
	pkghttp "github.com/vigolium/vigolium/pkg/deparos/http"
	"go.uber.org/zap"
)

// ExtensionConfirmEvent describes a server-side file extension that has been
// confirmed as a valid route on the target and queued for wordlist fuzzing
// (e.g. confirming ".php" triggers a sweep for hidden <word>.php files).
type ExtensionConfirmEvent struct {
	// Extension is the confirmed extension, normalized (lowercase, no dot).
	Extension string
	// Source is how it was confirmed: "observed", "fingerprint", or "probe".
	Source string
	// Detail is human-readable evidence (matched URL, stack name, probed file).
	Detail string
}

// defaultProbeFilenames are the high-signal base names tried per candidate
// extension during the active probe when none are configured.
var defaultProbeFilenames = []string{"index", "default", "login"}

// confirmStartURLExtensions runs the one-shot, start-of-scan confirmation pass:
// it confirms the start URL's own extension (observed), any extensions implied
// by the start URL's response fingerprint, and finally actively probes the
// remaining candidates. Only runs under ConfirmRequired.
func (e *Engine) confirmStartURLExtensions() {
	if !e.config.Extensions.ConfirmRequired {
		return
	}

	startURL, err := url.Parse(e.config.Target.StartURL)
	if err != nil {
		return
	}

	// Source 1: the start URL's own extension (e.g. target is /admin.php).
	if e.config.Extensions.ConfirmViaObserved {
		if _, ext := ExtractFilename(startURL.Path); ext != "" {
			e.confirmExtension(ext, "observed", e.config.Target.StartURL, 0)
		}
	}

	// Source 2: fingerprint the start URL's response headers/cookies — but only
	// when the start URL actually landed on a genuine app page. A stack
	// fingerprint taken from a 3xx redirect (commonly an off-host SSO/login
	// bounce), a 4xx/5xx error, or a login/SSO interstitial describes the
	// gateway/IdP, not the application, and produces phantom extensions (e.g. a
	// Salesforce 302 mis-read as PHP). The observed source above is still allowed
	// — a literal .php start URL proves a PHP handler ran even if it redirects —
	// and the active probe below is self-validating against the soft-404 baseline.
	if e.config.Extensions.ConfirmViaFingerprint && e.startURLHeader != nil {
		if e.startURLIsGenuineLanding() {
			e.confirmExtensionsFromHeaders(e.startURLHeader.Get, e.startURLHeader.Values("Set-Cookie"), "start URL", 0)
		} else {
			logger.Info("Skipping fingerprint-based extension confirmation — start URL is not a genuine landing page",
				zap.Int("status", e.startURLStatus),
				zap.Bool("login_or_sso", e.startURLIsLogin))
		}
	}

	// Source 3: actively probe the residual candidates that nothing else
	// revealed. This is the fallback that keeps rewrite-heavy apps (no visible
	// extension, no tech header) from being skipped entirely.
	if e.config.Extensions.ConfirmViaProbe {
		e.probeCandidateExtensions(startURLDirectory(startURL), 0)
	}
}

// startURLIsGenuineLanding reports whether the start URL's response is a real
// application page whose headers can be trusted as a server-stack fingerprint.
// It rejects 3xx redirects (often an off-host SSO/login bounce), 4xx/5xx errors,
// and login/SSO interstitials — in all of those the response describes a
// gateway/IdP rather than the app, so fingerprinting an extension off it is a
// false positive. An unknown status (0, e.g. the probe never ran) is treated as
// not-genuine so the fingerprint source stays off rather than guessing.
func (e *Engine) startURLIsGenuineLanding() bool {
	if e.startURLStatus < 200 || e.startURLStatus >= 300 {
		return false
	}
	if e.startURLIsLogin {
		return false
	}
	return true
}

// confirmExtensionsFromHeaders maps response headers/cookies to a server stack
// and confirms that stack's candidate extensions.
func (e *Engine) confirmExtensionsFromHeaders(getHeader func(string) string, setCookies []string, where string, depth uint16) {
	for _, sig := range config.DetectTechExtensions(getHeader, setCookies) {
		for _, ext := range sig.Extensions {
			e.confirmExtension(ext, "fingerprint", sig.Tech+" via "+where, depth)
		}
	}
}

// probeCandidateExtensions GETs a few high-signal filenames per unconfirmed
// candidate and confirms the extension if the analyzer reports a real hit
// (distinct from the per-extension soft-404 / catch-all baseline).
func (e *Engine) probeCandidateExtensions(dirURL *url.URL, depth uint16) {
	if dirURL == nil || e.httpClient == nil || e.analyzer == nil {
		return
	}

	names := e.config.Extensions.ProbeFilenames
	if len(names) == 0 {
		names = defaultProbeFilenames
	}

	// Probe candidates concurrently (bounded) to hide network latency on the
	// startup path; each extension's filenames are still tried in order with an
	// early exit on the first hit. confirmExtension is concurrency-safe.
	const maxConcurrentProbes = 6
	sem := make(chan struct{}, maxConcurrentProbes)
	var wg sync.WaitGroup

	for _, ext := range e.candidateExtensions() {
		ne := normalizeExt(ext)
		if ne == "" || e.isExtensionConfirmed(ne) {
			continue
		}
		if e.ctx.Err() != nil {
			break
		}

		wg.Add(1)
		sem <- struct{}{}
		go func(ext string) {
			defer wg.Done()
			defer func() { <-sem }()
			for _, name := range names {
				if e.ctx.Err() != nil {
					return
				}
				if e.probeExtensionRoute(dirURL, name, ext, depth) {
					return // confirmed — stop probing this extension
				}
			}
		}(ne)
	}

	wg.Wait()
}

// probeExtensionRoute fetches <dir>/<name>.<ext> and confirms the extension if
// the analyzer classifies the response as a genuine resource (not a soft-404 or
// catch-all). Returns true on confirmation.
func (e *Engine) probeExtensionRoute(dirURL *url.URL, name, ext string, depth uint16) bool {
	probe := *dirURL
	probe.Path = strings.TrimSuffix(dirURL.Path, "/") + "/" + name + "." + ext
	probe.RawQuery = ""
	probe.Fragment = ""

	req, err := pkghttp.NewRequest(probe.String()).Headers(e.config.Engine.CustomHeaders).Build()
	if err != nil {
		return false
	}

	rc, err := e.httpClient.Send(e.ctx, req)
	if err != nil {
		return false
	}
	defer rc.Close()

	found, err := e.analyzer.Analyze(e.ctx, req, rc)
	if err != nil || !found {
		return false
	}

	return e.confirmExtension(ext, "probe", name+"."+ext, depth)
}

// confirmExtension promotes a candidate extension to the confirmed/fuzz set on
// first confirmation, emits the console + log notice, and triggers the wordlist
// sweep for that extension. Returns true if this call performed the (first)
// confirmation. Safe to call concurrently and repeatedly for the same ext.
func (e *Engine) confirmExtension(ext, source, detail string, depth uint16) bool {
	ne := normalizeExt(ext)
	if ne == "" || !e.isCandidateExtension(ne) {
		return false
	}

	if !e.markExtensionConfirmed(ne) {
		return false // already confirmed by an earlier source
	}

	// Surface the extension to the factory's observed-extension task paths. The
	// legacy seenExtensions dedup is not touched here: under ConfirmRequired the
	// observed handler that consults it is gated off.
	e.AddObservedExtension(ne)

	if e.extensionConfirmCallback != nil {
		e.extensionConfirmCallback(ExtensionConfirmEvent{Extension: ne, Source: source, Detail: detail})
	}
	logger.Info("Extension confirmed as valid route — queuing wordlist fuzz",
		zap.String("extension", ne),
		zap.String("source", source),
		zap.String("detail", detail))

	if e.config.Extensions.TestObserved {
		e.generateObservedExtensionTasks(ne, depth)
	}
	return true
}

// markExtensionConfirmed records ext as confirmed and returns true if it was not
// already confirmed (i.e. this is the first confirmation).
func (e *Engine) markExtensionConfirmed(ext string) bool {
	e.confirmedExtMu.Lock()
	defer e.confirmedExtMu.Unlock()
	if _, ok := e.confirmedExtensions[ext]; ok {
		return false
	}
	e.confirmedExtensions[ext] = struct{}{}
	return true
}

// isExtensionConfirmed reports whether ext has already been confirmed.
func (e *Engine) isExtensionConfirmed(ext string) bool {
	e.confirmedExtMu.Lock()
	defer e.confirmedExtMu.Unlock()
	_, ok := e.confirmedExtensions[ext]
	return ok
}

// candidateExtensions returns the configured candidate set, falling back to the
// package defaults if unset.
func (e *Engine) candidateExtensions() []string {
	if len(e.config.Extensions.Candidates) > 0 {
		return e.config.Extensions.Candidates
	}
	return config.DefaultCandidateExtensions
}

// candidateExtensionSet returns the candidate extensions as a normalized lookup
// set, built once (the config list is read-only for the engine's lifetime).
func (e *Engine) candidateExtensionSet() map[string]struct{} {
	e.candidateExtOnce.Do(func() {
		set := make(map[string]struct{})
		for _, c := range e.candidateExtensions() {
			if ne := normalizeExt(c); ne != "" {
				set[ne] = struct{}{}
			}
		}
		e.candidateExtSet = set
	})
	return e.candidateExtSet
}

// isCandidateExtension reports whether ext (normalized) is eligible for
// confirmation + fuzzing.
func (e *Engine) isCandidateExtension(ext string) bool {
	_, ok := e.candidateExtensionSet()[ext]
	return ok
}

// normalizeExt lowercases and strips any leading dot(s)/whitespace from ext.
func normalizeExt(ext string) string {
	ext = strings.TrimSpace(strings.ToLower(ext))
	ext = strings.TrimLeft(ext, ".")
	return ext
}

// startURLDirectory returns the directory URL of the start URL (filename and
// query stripped), used as the base for active extension probes.
func startURLDirectory(u *url.URL) *url.URL {
	if u == nil {
		return nil
	}
	dir := *u
	dir.RawQuery = ""
	dir.Fragment = ""
	p := dir.Path
	if p == "" {
		p = "/"
	}
	if !strings.HasSuffix(p, "/") {
		if i := strings.LastIndex(p, "/"); i >= 0 {
			p = p[:i+1]
		} else {
			p = "/"
		}
	}
	dir.Path = p
	return &dir
}
