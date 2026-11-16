package browsercookie

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
)

// Format names an output encoding.
type Format string

const (
	// FormatJSON is this package's own cookie shape, one object per cookie.
	FormatJSON Format = "json"
	// FormatJSONL is the same, one cookie per line.
	FormatJSONL Format = "jsonl"
	// FormatPlaywright is a Playwright storageState document, ready for
	// browser.newContext({storageState}) or context.addCookies().
	FormatPlaywright Format = "playwright"
	// FormatNetscape is the Netscape cookie-file format curl reads with -b.
	FormatNetscape Format = "netscape"
	// FormatHeader is a single Cookie request-header value.
	FormatHeader Format = "header"
	// FormatPlaywrightInit is a JavaScript snippet that restores
	// sessionStorage, which a storageState document cannot carry.
	FormatPlaywrightInit Format = "playwright-init"
)

// Formats returns every supported format, in a stable order.
func Formats() []Format {
	return []Format{FormatJSON, FormatJSONL, FormatPlaywright, FormatPlaywrightInit, FormatNetscape, FormatHeader}
}

// FormatList renders the supported formats as a comma-separated list, for help
// text and errors.
//
// Built from Formats() rather than written out: hand-written copies had already
// gone stale — they omitted playwright-init, a real format with its own
// renderer, and that incomplete list reached the generated agent reference.
func FormatList() string {
	formats := Formats()
	names := make([]string, 0, len(formats))
	for _, f := range formats {
		names = append(names, string(f))
	}
	return strings.Join(names, ", ")
}

// ParseFormat maps a CLI spelling to a Format.
func ParseFormat(s string) (Format, error) {
	f := Format(strings.ToLower(strings.TrimSpace(s)))
	switch f {
	case "":
		return FormatJSON, nil
	case FormatJSON, FormatJSONL, FormatPlaywright, FormatPlaywrightInit, FormatNetscape, FormatHeader:
		return f, nil
	case "storage-state", "storagestate":
		return FormatPlaywright, nil
	case "init-script", "session-init":
		return FormatPlaywrightInit, nil
	case "cookiejar", "curl", "txt":
		return FormatNetscape, nil
	}
	return "", fmt.Errorf("unknown format %q (want %s)", s, FormatList())
}

// RenderOptions tunes an export.
type RenderOptions struct {
	// Origins is the local storage to include. Only the Playwright
	// storageState has a place for it; every other format drops it, which is
	// why --with-storage warns when paired with one of those.
	Origins []Origin
	// SameSite overrides the SameSite attribute written for every cookie.
	// Empty means [DefaultSameSite] is used wherever the store did not record
	// one — which, for Chromium stores, is everywhere.
	SameSite string
}

// DefaultSameSite is what an exported cookie claims when the store did not
// record the attribute.
//
// Lax is Chrome's own default for a cookie that arrived without a SameSite
// attribute, so it is the honest guess. It is still a guess: a cookie that was
// really set SameSite=None — any cookie meant to survive a cross-site request,
// which includes most SSO and embedded-widget sessions — will not work when
// replayed as Lax. That is what RenderOptions.SameSite is for, and why the
// result carries a warning whenever a Secure cookie is exported.
const DefaultSameSite = "Lax"

// resolveSameSite decides the attribute to write for one cookie.
//
// A "None" override is withheld from a cookie that is not Secure. SameSite=None
// without the Secure attribute is invalid, and a browser does not merely
// ignore the attribute — it rejects the whole cookie. So the flag an operator
// reaches for to make a cross-site flow work would, applied blindly, silently
// drop every non-Secure cookie in the export: on a real Google profile that is
// SID, APISID and SIDCC, which is to say the session. Those keep the default
// instead, which is the behaviour they already had.
func resolveSameSite(c Cookie, opts RenderOptions) string {
	if override := normalizeSameSite(opts.SameSite); override != "" {
		if override == "None" && !c.Secure {
			return DefaultSameSite
		}
		return override
	}
	if c.SameSite != SameSiteUnknown {
		return c.SameSite
	}
	return DefaultSameSite
}

// SameSiteNoneWithheld counts the cookies a "none" override cannot be applied
// to because they are not Secure, so a caller can say so rather than let the
// export look uniform.
func SameSiteNoneWithheld(cookies []Cookie, opts RenderOptions) int {
	if normalizeSameSite(opts.SameSite) != "None" {
		return 0
	}
	n := 0
	for _, c := range cookies {
		if !c.Secure {
			n++
		}
	}
	return n
}

// normalizeSameSite maps a caller's spelling to the canonical attribute value,
// returning "" for an unrecognized one.
func normalizeSameSite(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "strict":
		return "Strict"
	case "lax":
		return "Lax"
	case "none":
		return "None"
	default:
		return ""
	}
}

// ValidateSameSite checks a caller-supplied SameSite override.
func ValidateSameSite(s string) error {
	if strings.TrimSpace(s) == "" || normalizeSameSite(s) != "" {
		return nil
	}
	return fmt.Errorf("unknown same-site %q (want strict, lax, or none)", s)
}

// Render writes the cookies to w in the given format.
func Render(w io.Writer, cookies []Cookie, format Format, opts RenderOptions) error {
	switch format {
	case FormatPlaywright:
		return renderPlaywright(w, cookies, opts)
	case FormatPlaywrightInit:
		return renderPlaywrightInit(w, opts.Origins)
	case FormatNetscape:
		return renderNetscape(w, cookies, opts)
	case FormatHeader:
		return renderHeader(w, cookies)
	case FormatJSONL:
		return renderJSONL(w, cookies, opts.Origins)
	case FormatJSON, "":
		return renderJSON(w, cookies, opts.Origins)
	default:
		return fmt.Errorf("unknown format %q", format)
	}
}

// playwrightState is Playwright's storageState document.
//
// Origins is always present, even empty: Playwright accepts the document
// either way, but a consumer that merges local storage into it expects the key
// to exist, and an absent array has repeatedly been read as "this export lost
// the local storage" rather than "this export never carried any".
type playwrightState struct {
	Cookies []playwrightCookie `json:"cookies"`
	Origins []playwrightOrigin `json:"origins"`
}

type playwrightOrigin struct {
	Origin       string                  `json:"origin"`
	LocalStorage []playwrightStorageItem `json:"localStorage"`
}

// playwrightStorageItem is one local-storage entry in Playwright's shape. The
// field names are name/value, not key/value: Playwright rejects the latter.
type playwrightStorageItem struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// playwrightOrigins converts read origins into storageState's shape.
//
// Two kinds are dropped. An origin whose storage is empty adds a line that
// promises state the document does not carry. A PARTITIONED origin is third
// party storage keyed to some other top-level site, and storageState has no
// way to say so — restoring it as a plain origin would write one site's view of
// another into its first-party bucket. On a real profile a quarter of the
// origins are partitioned, so this is the common case, not a corner.
func playwrightOrigins(origins []Origin) []playwrightOrigin {
	out := make([]playwrightOrigin, 0, len(origins))
	for _, o := range origins {
		if len(o.LocalStorage) == 0 || o.Partitioned {
			continue
		}
		items := make([]playwrightStorageItem, 0, len(o.LocalStorage))
		for _, it := range o.LocalStorage {
			// A conversion, not a literal: it stops compiling the moment the
			// two shapes diverge, which is the guard worth having between an
			// internal type and a wire format someone else parses.
			items = append(items, playwrightStorageItem(it))
		}
		out = append(out, playwrightOrigin{Origin: o.Origin, LocalStorage: items})
	}
	return out
}

// PartitionedOrigins counts the origins an export must hold back because they
// are third-party partitioned storage.
func PartitionedOrigins(origins []Origin) int {
	n := 0
	for _, o := range origins {
		if o.Partitioned {
			n++
		}
	}
	return n
}

// renderPlaywrightInit writes a script that restores sessionStorage.
//
// It exists because Playwright's storageState has fields for cookies and
// localStorage and nothing else — sessionStorage is per-tab state the format
// does not model. Restoring it means running code in the page before it loads,
// which is what context.addInitScript is for. Emitting the snippet rather than
// documenting it keeps the handoff a file an agent can use.
//
// The script keys its data by origin and reads window.location.origin, so one
// file covers every origin in the export and writes each one's entries only on
// its own pages. Each setItem is guarded: storage can be disabled or full, and
// one rejected key must not abort the rest.
func renderPlaywrightInit(w io.Writer, origins []Origin) error {
	byOrigin := map[string]map[string]string{}
	for _, o := range origins {
		if o.Partitioned || len(o.SessionStorage) == 0 {
			continue
		}
		entries := make(map[string]string, len(o.SessionStorage))
		for _, item := range o.SessionStorage {
			entries[item.Name] = item.Value
		}
		byOrigin[o.Origin] = entries
	}
	data, err := json.MarshalIndent(byOrigin, "", "  ")
	if err != nil {
		return err
	}

	const header = `// sessionStorage captured by ` + "`vigolium kit cookies`" + `.
//
// A Playwright storageState carries cookies and localStorage only, so this
// restores the rest. Treat it as a credential: the values below are live.
//
//   const ctx = await browser.newContext({ storageState: 'state.json' });
//   await ctx.addInitScript({ path: 'session-init.js' });
//
// It writes each origin's entries only on that origin's pages.
`
	if _, err := io.WriteString(w, header); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "(() => {\n  const byOrigin = %s;\n", data); err != nil {
		return err
	}
	const body = `  const entries = byOrigin[window.location.origin];
  if (!entries) return;
  for (const [key, value] of Object.entries(entries)) {
    try {
      window.sessionStorage.setItem(key, value);
    } catch (e) {
      // Storage disabled or full: keep going, a partial restore beats none.
    }
  }
})();
`
	_, err = io.WriteString(w, body)
	return err
}

// StorageCapableFormats are the formats with somewhere to put local storage.
// Everything else is a cookie-only wire format.
func StorageCapableFormats() []Format {
	return []Format{FormatPlaywright, FormatPlaywrightInit, FormatJSON, FormatJSONL}
}

// SessionStorageItems counts the sessionStorage entries across origins.
func SessionStorageItems(origins []Origin) int {
	n := 0
	for _, o := range origins {
		if !o.Partitioned {
			n += len(o.SessionStorage)
		}
	}
	return n
}

// FormatCarriesStorage reports whether f can represent local storage.
func FormatCarriesStorage(f Format) bool {
	for _, known := range StorageCapableFormats() {
		if f == known {
			return true
		}
	}
	return false
}

// playwrightCookie is one cookie in Playwright's shape. Expires is seconds
// since the epoch as a number, with -1 meaning a session cookie — not the RFC
// 3339 string the rest of this package uses, and not Chrome's microseconds.
type playwrightCookie struct {
	Name     string  `json:"name"`
	Value    string  `json:"value"`
	Domain   string  `json:"domain"`
	Path     string  `json:"path"`
	Expires  float64 `json:"expires"`
	HTTPOnly bool    `json:"httpOnly"`
	Secure   bool    `json:"secure"`
	SameSite string  `json:"sameSite"`
}

// PlaywrightSessionExpiry is the Expires value Playwright reads as "session
// cookie": it is not a timestamp, and writing 0 there instead creates a cookie
// that expired in 1970 and is dropped on load.
const PlaywrightSessionExpiry = -1

func renderPlaywright(w io.Writer, cookies []Cookie, opts RenderOptions) error {
	state := playwrightState{
		Cookies: make([]playwrightCookie, 0, len(cookies)),
		Origins: playwrightOrigins(opts.Origins),
	}
	for _, c := range cookies {
		expires := float64(PlaywrightSessionExpiry)
		if !c.Session() {
			expires = float64(c.Expires.Unix())
		}
		path := c.Path
		if path == "" {
			path = "/"
		}
		state.Cookies = append(state.Cookies, playwrightCookie{
			Name:     c.Name,
			Value:    c.Value,
			Domain:   c.Domain,
			Path:     path,
			Expires:  expires,
			HTTPOnly: c.HTTPOnly,
			Secure:   c.Secure,
			SameSite: resolveSameSite(c, opts),
		})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(state)
}

// renderNetscape writes the cookie-file format curl reads with -b/--cookie.
//
// The `#HttpOnly_` domain prefix is curl's convention rather than Netscape's:
// without it curl drops the HttpOnly flag on load, and a session whose auth
// cookie is HttpOnly — which it should be — comes back subtly different from
// what the browser holds.
func renderNetscape(w io.Writer, cookies []Cookie, opts RenderOptions) error {
	if _, err := fmt.Fprint(w, "# Netscape HTTP Cookie File\n# Written by vigolium kit cookies. Treat as credentials.\n\n"); err != nil {
		return err
	}
	for _, c := range cookies {
		domain := c.Domain
		includeSubdomains := "FALSE"
		if strings.HasPrefix(domain, ".") {
			includeSubdomains = "TRUE"
		}
		prefix := ""
		if c.HTTPOnly {
			prefix = "#HttpOnly_"
		}
		path := c.Path
		if path == "" {
			path = "/"
		}
		secure := "FALSE"
		if c.Secure {
			secure = "TRUE"
		}
		var expires int64 // 0 is the format's "session cookie"
		if !c.Session() {
			expires = c.Expires.Unix()
		}
		if _, err := fmt.Fprintf(w, "%s%s\t%s\t%s\t%s\t%d\t%s\t%s\n",
			prefix, domain, includeSubdomains, path, secure, expires, c.Name, c.Value); err != nil {
			return err
		}
	}
	return nil
}

// renderHeader writes a single Cookie request-header value.
//
// A Cookie header carries no domain or path, so it is only meaningful for one
// host. Duplicate names are collapsed, keeping the most specific path, which is
// the one a browser would send first.
func renderHeader(w io.Writer, cookies []Cookie) error {
	best := make(map[string]Cookie, len(cookies))
	var order []string
	for _, c := range cookies {
		prev, seen := best[c.Name]
		if !seen {
			order = append(order, c.Name)
			best[c.Name] = c
			continue
		}
		if len(c.Path) > len(prev.Path) {
			best[c.Name] = c
		}
	}
	sort.Strings(order)
	parts := make([]string, 0, len(order))
	for _, name := range order {
		parts = append(parts, name+"="+best[name].Value)
	}
	_, err := fmt.Fprintln(w, strings.Join(parts, "; "))
	return err
}

// renderJSON writes a bare cookie array, or — once local storage is in play —
// an object carrying both. The shape changes with the content rather than
// always being an object, because the array is the established output and a
// caller reading `.[0].name` should not break for asking for storage.
func renderJSON(w io.Writer, cookies []Cookie, origins []Origin) error {
	if cookies == nil {
		cookies = []Cookie{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if len(origins) == 0 {
		return enc.Encode(cookies)
	}
	return enc.Encode(struct {
		Cookies []Cookie `json:"cookies"`
		Origins []Origin `json:"origins"`
	}{cookies, origins})
}

// renderJSONL writes one object per line: every cookie, then every origin.
// Each line is tagged so a consumer reading the stream can tell them apart.
func renderJSONL(w io.Writer, cookies []Cookie, origins []Origin) error {
	enc := json.NewEncoder(w)
	for _, c := range cookies {
		if err := enc.Encode(struct {
			Kind string `json:"kind"`
			Cookie
		}{"cookie", c}); err != nil {
			return err
		}
	}
	for _, o := range origins {
		if err := enc.Encode(struct {
			Kind string `json:"kind"`
			Origin
		}{"origin", o}); err != nil {
			return err
		}
	}
	return nil
}

// DistinctDomains returns the distinct domain attributes present, sorted. The
// Cookie-header export uses it to tell the caller when it has flattened
// cookies from more than one host into a header that can only serve one.
func DistinctDomains(cookies []Cookie) []string {
	seen := make(map[string]bool, len(cookies))
	var out []string
	for _, c := range cookies {
		if seen[c.Domain] {
			continue
		}
		seen[c.Domain] = true
		out = append(out, c.Domain)
	}
	sort.Strings(out)
	return out
}

// Redact masks a cookie value for display, keeping a short tail so two cookies
// can be told apart without exposing either.
//
// The mask is a fixed width rather than the value's own length. Session
// cookies run to hundreds of characters — a Google NID is over 600 — and a
// mask that tracked the length turned every listing into one unreadable line
// per cookie. The length is worth knowing (it distinguishes a JWT from a
// flag), so it is reported as a number in its own column instead of being
// drawn.
//
// A value shorter than redactTailMinLen keeps no tail at all: four characters
// of a six-character PIN or short token are most of the secret, so a short
// value is the bare mask.
func Redact(value string) string {
	const (
		keep = 4
		mask = 8
	)
	if value == "" {
		return ""
	}
	if len(value) < redactTailMinLen {
		return strings.Repeat("*", mask)
	}
	return strings.Repeat("*", mask) + value[len(value)-keep:]
}

// redactTailMinLen is the shortest value Redact keeps a tail of: at 12
// characters the four shown are a third of the value, below it they are most
// of it.
const redactTailMinLen = 12
