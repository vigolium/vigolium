package spitolas

import (
	"github.com/vigolium/vigolium/pkg/spitolas/internal/browser"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
)

// DialogPolicy selects how the browser answers a JavaScript dialog after it has
// been recorded. Recording happens first under every policy, so dialog-based
// confirmation (stored XSS, DOM XSS canaries) never depends on the answer.
type DialogPolicy = config.DialogPolicy

const (
	// DialogRecordDismiss (default) accepts alert and beforeunload and dismisses
	// confirm/prompt, so no dialog can authorize an application change.
	DialogRecordDismiss = config.DialogRecordDismiss
	// DialogAcceptAll accepts every dialog — the pre-policy behavior.
	DialogAcceptAll = config.DialogAcceptAll
)

// DialogPolicies lists every accepted DialogPolicy value, default first.
var DialogPolicies = []DialogPolicy{DialogRecordDismiss, DialogAcceptAll}

// StealthModes lists the accepted SpiderConfig.Stealth / ProbeConfig.Stealth
// values, default (auto) first. Auto is on for the default chromium engine and
// off for ungoogled/fingerprint, which bring their own fingerprint flags.
var StealthModes = config.StealthModes

// TabIsolationModes lists the accepted SpiderConfig.TabIsolation values,
// default (shared) first: shared puts every tab in the browser's default
// context (one cookie jar); context gives each extra tab its own.
var TabIsolationModes = config.TabIsolationModes

// MaxTabs caps SpiderConfig.Tabs.
const MaxTabs = config.MaxTabs

// InteractionPolicy is the single table of what a browser run is permitted to
// change. One struct, carried from resolved operator config through to every
// dispatch gate, so a control cannot describe more than it enforces. Its fields
// match config.InteractionPolicy exactly, so the two convert directly and a
// field added to one alone fails to compile.
type InteractionPolicy struct {
	EditFields      bool // type into / toggle / select controls
	SubmitForms     bool // dispatch a submit through any mechanism
	UploadFiles     bool // attach a generated fixture to a file input
	DownloadFiles   bool // let the browser save a download to disk
	RegisterAccount bool // complete a signup form
	LoginAttempts   bool // submit credentials to a confirmed login form
	DialogResponse  DialogPolicy
}

// PolicyCategories is the order and the names the policy report renders, and
// the drift guard's reference list — a runner test pins it against Fields(),
// against the spidering.interaction YAML keys it matches, and against the
// config-side pointer struct that validates them, so a new category cannot
// appear in one of those and not the others.
var PolicyCategories = []string{"edit_fields", "submit_forms", "upload_files",
	"download_files", "register_account", "login_attempts", "dialogs"}

// DefaultInteractionPolicy is what a crawl may do when the operator says
// nothing: edit fields, submit forms and attach the benign generated upload
// fixture (the crawl's discovery depends on all three — a file input left empty
// hides the upload surface), never create accounts, attempt logins or download,
// and dismiss confirm/prompt dialogs. The runner may still turn login attempts
// on from the scan intensity; see the spidering.interaction docs.
func DefaultInteractionPolicy() InteractionPolicy {
	return InteractionPolicy(config.DefaultInteractionPolicy())
}

// Fields returns the policy keyed by PolicyCategories — booleans for the
// permission categories and the dialog policy string for "dialogs". Stable
// machine shape for reports and artifact manifests.
func (p InteractionPolicy) Fields() map[string]any {
	dialogs := p.DialogResponse
	if dialogs == "" {
		dialogs = DialogRecordDismiss
	}
	return map[string]any{
		"edit_fields":      p.EditFields,
		"submit_forms":     p.SubmitForms,
		"upload_files":     p.UploadFiles,
		"download_files":   p.DownloadFiles,
		"register_account": p.RegisterAccount,
		"login_attempts":   p.LoginAttempts,
		"dialogs":          string(dialogs),
	}
}

// legacyPolicy is the policy a SpiderConfig without an explicit Policy implies:
// the defaults, with the pre-policy switches (NoForms, SelfRegister,
// LoginCredentialAttempts) applied on top so existing callers keep their
// behavior.
func (cfg SpiderConfig) legacyPolicy() InteractionPolicy {
	p := DefaultInteractionPolicy()
	p.EditFields = !cfg.NoForms
	p.SubmitForms = !cfg.NoForms
	p.UploadFiles = !cfg.NoForms // attaching a file is a field edit
	p.RegisterAccount = cfg.SelfRegister
	p.LoginAttempts = cfg.LoginCredentialAttempts
	return p
}

// EffectivePolicy returns the policy the crawl enforces: Policy when set,
// otherwise the one the legacy switches imply.
func (cfg SpiderConfig) EffectivePolicy() InteractionPolicy {
	if cfg.Policy != nil {
		return *cfg.Policy
	}
	return cfg.legacyPolicy()
}

// BrowserCompat lists the browser security exceptions a crawl runs with. Each
// field relaxes exactly one ordinary Chromium boundary; see the field comments
// on config.BrowserCompat, which this names.
//
// An alias rather than a matching struct, like DialogPolicy above: the launcher
// is the authority on what each exception does, and a copy here would be ~20
// lines of struct plus ~15 of per-field prose that has to keep agreeing with it.
type BrowserCompat = config.BrowserCompat

// DefaultBrowserCompat is the posture when the operator configures nothing:
// sandbox on, mixed content blocked, same-origin policy intact, certificate
// errors ignored (see IgnoreTLSErrors).
func DefaultBrowserCompat() BrowserCompat {
	return config.DefaultBrowserCompat()
}

// InsecureBrowserCompat turns every exception on: the posture --browser-insecure
// asks for, meant for local test apps only. The flag itself travels through
// config (SpideringBrowserCompat.SetAll), so this is the value that posture is
// asserted against rather than the path it takes.
func InsecureBrowserCompat() BrowserCompat {
	return BrowserCompat{NoSandbox: true, IgnoreTLSErrors: true, AllowInsecureContent: true, DisableWebSecurity: true}
}

// EffectiveCompat returns BrowserCompat when set, otherwise the defaults.
func (cfg SpiderConfig) EffectiveCompat() BrowserCompat {
	if cfg.BrowserCompat != nil {
		return *cfg.BrowserCompat
	}
	return DefaultBrowserCompat()
}

// BrowserSecurity is the security posture a launch actually gets: the
// configured exceptions with the host's forced-sandbox decision applied.
type BrowserSecurity struct {
	BrowserCompat
	// SandboxForcedOff is true when the configuration asked for a sandbox and
	// the host could not provide one; SandboxReason names why.
	SandboxForcedOff bool
	SandboxReason    string
}

// EffectiveBrowserSecurity resolves c against this host. The sandbox decision
// is process-wide (see the browser package), so the answer matches what every
// launch in this run gets — including a Linux launch fallback that has already
// happened.
func EffectiveBrowserSecurity(c BrowserCompat) BrowserSecurity {
	s := BrowserSecurity{BrowserCompat: c}
	if !c.NoSandbox {
		if off, why := browser.SandboxDisabledReason(); off {
			s.NoSandbox = true
			s.SandboxForcedOff = true
			s.SandboxReason = why
		}
	}
	return s
}

// Fields returns the effective posture under stable keys for reports and
// artifact manifests: "sandbox" (on/off), "tls" (verify/ignore-errors),
// "mixed_content" (block/allow), "web_security" (on/off), plus
// "sandbox_reason" when the host forced the sandbox off.
func (s BrowserSecurity) Fields() map[string]any {
	pick := func(cond bool, yes, no string) string {
		if cond {
			return yes
		}
		return no
	}
	m := map[string]any{
		"sandbox":       pick(s.NoSandbox, "off", "on"),
		"tls":           pick(s.IgnoreTLSErrors, "ignore-errors", "verify"),
		"mixed_content": pick(s.AllowInsecureContent, "allow", "block"),
		"web_security":  pick(s.DisableWebSecurity, "off", "on"),
	}
	if s.SandboxForcedOff {
		m["sandbox_reason"] = s.SandboxReason
	}
	return m
}

// SecurityFieldOrder is the order report lines render Fields() in.
var SecurityFieldOrder = []string{"sandbox", "tls", "mixed_content", "web_security"}

// SetOffline disables every browser download fallback for the process
// (--offline): a missing browser fails with the install hint.
func SetOffline(v bool) { browser.SetOffline(v) }

// AuthMonitor is the crawl's view of the scan's live session:
// Credentials returns the current generation, headers and cookies; Observe
// feeds a response to the session's logged-out detector.
type AuthMonitor = config.AuthMonitor
