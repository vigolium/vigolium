package discovery

import (
	"net/url"
	"sort"
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

	// Source 1: the start URL's own extension (e.g. target is /admin.php) — but
	// only when the start URL was actually SERVED as that extension. Recon feeds
	// commonly seed known-probe paths (/Telerik.Web.UI.DialogHandler.aspx,
	// /overview/default.aspx, /Error.aspx) that a host 404s or 302s away; trusting
	// the ".aspx" suffix alone then confirms ASP.NET and queues a *.aspx wordlist
	// fuzz on a host that runs no ASP.NET at all. A 2xx (or a 401/403 auth wall
	// proving the handler exists) is required; a 3xx/404/5xx seed is not. The
	// active probe below is the fallback that still covers rewrite-heavy apps.
	if e.config.Extensions.ConfirmViaObserved {
		if _, ext := ExtractFilename(startURL.Path); ext != "" {
			if statusConfirmsServedExtension(e.startURLStatus) {
				e.confirmExtension(ext, "observed", e.config.Target.StartURL, 0)
			} else {
				logger.Info("Skipping observed start-URL extension confirmation — start URL was not served (redirect/404/5xx seed)",
					zap.String("extension", ext),
					zap.Int("status", e.startURLStatus))
			}
		}
	}

	// Source 2: fingerprint the start URL's response headers/cookies — but only
	// when the start URL actually landed on a genuine app page. A stack
	// fingerprint taken from a 3xx redirect (commonly an off-host SSO/login
	// bounce), a 4xx/5xx error, or a login/SSO interstitial describes the
	// gateway/IdP, not the application, and produces phantom extensions (e.g. a
	// Salesforce 302 mis-read as PHP). The observed source above applies its own
	// served-status gate, and the active probe below is self-validating against
	// the soft-404 baseline; both the observed and fingerprint sources are further
	// backstopped by the per-extension catch-all guard in confirmExtension.
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

	// Catch-all guard: the "observed" and "fingerprint" sources infer a
	// server-side stack from a URL/header that a modern SPA/CDN/catch-all host
	// answers regardless of what it actually runs (a junk 200 that reflects any
	// path). Before trusting them, verify the host does NOT serve a random
	// <nonce>.<ext> as a genuine resource. The active "probe" source is exempt —
	// it already validated the specific file against the soft-404 baseline.
	if source == "observed" || source == "fingerprint" {
		if e.extensionServedByCatchAll(ne) {
			logger.Info("Skipping extension confirmation — host answers a random <nonce> file as a catch-all (no real server-side stack)",
				zap.String("extension", ne),
				zap.String("source", source),
				zap.String("detail", detail))
			return false
		}
	}

	confirmed, conflict := e.reserveExtension(ne)
	if !confirmed {
		if conflict != "" {
			// A single application serves exactly one server-side stack, so a
			// second, incompatible one confirming means this host is answering
			// for extensions it does not run — a catch-all/SPA gateway echoing
			// every guessed path. Refuse rather than wordlist-fuzz a phantom
			// stack. The first family confirmed still fuzzes.
			logger.Info("Skipping extension confirmation — different server stack already confirmed (catch-all signal)",
				zap.String("extension", ne),
				zap.String("family", serverStackFamily(ne)),
				zap.String("confirmed_family", conflict),
				zap.String("source", source),
				zap.String("detail", detail))
		}
		return false // already confirmed, or refused by the catch-all guard
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

// serverExtCatchAllNonces are two improbable base names probed per candidate
// extension to detect a catch-all host: if the target answers <nonce>.<ext> as a
// genuine resource for BOTH, it 200s (and reflects) arbitrary paths and cannot be
// trusted to prove it runs that server-side stack. Requiring two guards against a
// lone transient/edge 200 misreading a real host as a catch-all.
var serverExtCatchAllNonces = [2]string{
	"vig0lium-no-such-route-7f3a9c",
	"vig0lium-absent-handler-1b8e2d",
}

// extensionServedByCatchAll reports whether the target answers random,
// certainly-nonexistent <nonce>.<ext> paths with a 2xx success — the signature of
// a modern SPA/CDN/catch-all host that 200s (and reflects) any path. On such a
// host an observed or fingerprinted .<ext> URL is no proof the server runs that
// stack, so those confirmation sources consult this guard first. The verdict is
// probed once per extension and cached. Fails open (returns false) whenever the
// check cannot run, so a genuine stack still confirms when the network is
// unavailable.
func (e *Engine) extensionServedByCatchAll(ext string) bool {
	if e.httpClient == nil {
		return false
	}

	e.extCatchAllMu.Lock()
	if v, ok := e.extCatchAll[ext]; ok {
		e.extCatchAllMu.Unlock()
		return v
	}
	e.extCatchAllMu.Unlock()

	verdict := e.probeExtensionCatchAll(ext)

	e.extCatchAllMu.Lock()
	if e.extCatchAll == nil {
		e.extCatchAll = make(map[string]bool)
	}
	e.extCatchAll[ext] = verdict
	e.extCatchAllMu.Unlock()
	return verdict
}

// probeExtensionCatchAll fetches the improbable <nonce>.<ext> filenames in the
// start URL's directory and reports whether ALL of them return a 2xx success. A
// genuine server-side host 404s (or 401/403/5xx) a nonexistent file, so a single
// non-2xx clears the host; only a host that serves every unguessable guess as a
// success is treated as a catch-all. Status-based on purpose: it stays correct
// even when the soft-404 baseline was itself learned from the catch-all shell
// (which would make the analyzer treat every path — real or fake — as not-found).
func (e *Engine) probeExtensionCatchAll(ext string) bool {
	base := e.catchAllProbeBase()
	if base == "" {
		return false
	}
	for _, nonce := range serverExtCatchAllNonces {
		if e.ctx.Err() != nil {
			return false
		}
		probe := jsBundleProbeURL(base, nonce, ext)
		if probe == nil {
			return false
		}
		if e.spiderScope != nil && !e.spiderScope.IsInScope(probe) {
			return false
		}
		if !e.extensionNonceServed(probe) {
			return false // a nonexistent file did not 200 → not a catch-all
		}
	}
	return true
}

// catchAllProbeBase returns the base directory (trailing slash) in which the
// catch-all nonce probes are issued: the start URL's directory, falling back to
// its scheme+host root. Returns "" when the start URL cannot be parsed.
func (e *Engine) catchAllProbeBase() string {
	startURL, err := url.Parse(e.config.Target.StartURL)
	if err != nil {
		return ""
	}
	if dir := startURLDirectory(startURL); dir != nil {
		s := dir.String()
		if !strings.HasSuffix(s, "/") {
			s += "/"
		}
		return s
	}
	return startURL.Scheme + "://" + startURL.Host + "/"
}

// extensionNonceServed fetches u (a random <nonce>.<ext> path) and reports whether
// the host answered with a 2xx success. A genuine server-side host 404s (or
// 401/403/5xx) a nonexistent file; only a catch-all/SPA/CDN answers an unguessable
// path with a success.
func (e *Engine) extensionNonceServed(u *url.URL) bool {
	req, err := pkghttp.NewRequest(u.String()).Headers(e.config.Engine.CustomHeaders).Build()
	if err != nil {
		return false
	}
	rc, err := e.httpClient.Send(e.ctx, req)
	if err != nil {
		return false
	}
	defer rc.Close()

	resp := rc.Response()
	return resp != nil && pkghttp.IsSuccessStatus(resp.StatusCode)
}

// reserveExtension atomically decides whether ext may be confirmed and, if so,
// records it. It returns:
//
//	confirmed=true             → first confirmation; the caller should proceed.
//	confirmed=false, conflict="" → already confirmed (a no-op repeat).
//	confirmed=false, conflict≠"" → refused: a different server-side stack family
//	                               (conflict) is already confirmed, so this host
//	                               is behaving as a catch-all (see confirmExtension).
//
// The family check and the mark happen under one lock so concurrent confirmations
// of two incompatible stacks can't both slip through.
func (e *Engine) reserveExtension(ext string) (confirmed bool, conflict string) {
	e.confirmedExtMu.Lock()
	defer e.confirmedExtMu.Unlock()
	if _, ok := e.confirmedExtensions[ext]; ok {
		return false, ""
	}
	if fam := serverStackFamily(ext); fam != "" {
		for confExt := range e.confirmedExtensions {
			if other := serverStackFamily(confExt); other != "" && other != fam {
				return false, other
			}
		}
	}
	e.confirmedExtensions[ext] = struct{}{}
	return true, ""
}

// serverStackFamily maps a server-side route extension to its mutually-exclusive
// stack family — a given application serves exactly one of these (PHP xor classic/
// modern ASP.NET xor Java/JSP/Struts xor ColdFusion xor CGI). Returns "" for any
// extension that is not a server-side stack (so it is never subject to the
// one-stack-per-app catch-all guard).
func serverStackFamily(ext string) string {
	switch ext {
	case "php", "php3", "php4", "php5", "phtml", "phtm":
		return "php"
	case "asp", "aspx", "ashx", "asmx":
		return "aspnet"
	case "jsp", "jspx", "jspa", "do", "action":
		return "java"
	case "cfm", "cfml":
		return "coldfusion"
	case "cgi", "pl":
		return "cgi"
	default:
		return ""
	}
}

// isExtensionConfirmed reports whether ext has already been confirmed.
func (e *Engine) isExtensionConfirmed(ext string) bool {
	e.confirmedExtMu.Lock()
	defer e.confirmedExtMu.Unlock()
	_, ok := e.confirmedExtensions[ext]
	return ok
}

// confirmedExtensionsSnapshot returns the confirmed extensions, sorted.
func (e *Engine) confirmedExtensionsSnapshot() []string {
	e.confirmedExtMu.Lock()
	out := make([]string, 0, len(e.confirmedExtensions))
	for ext := range e.confirmedExtensions {
		out = append(out, ext)
	}
	e.confirmedExtMu.Unlock()
	sort.Strings(out)
	return out
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
