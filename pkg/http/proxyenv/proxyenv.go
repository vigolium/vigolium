// Package proxyenv resolves which proxy, if any, a target-facing request goes
// through, and says where that choice came from.
//
// The rules:
//   - --proxy (the CLI value) proxies every request, whatever its scheme and
//     host. NO_PROXY does not apply to it: an operator who typed a proxy wants
//     to see everything in it.
//   - Otherwise the environment decides, by the request's scheme: HTTPS_PROXY
//     (https_proxy) for https, HTTP_PROXY (http_proxy) for http, ALL_PROXY
//     (all_proxy) for either when the scheme's own variable is unset.
//   - NO_PROXY (no_proxy) exempts hosts from an environment proxy: "*", a host
//     or domain suffix ("example.com" and ".example.com" both match
//     sub.example.com), an IP, a CIDR, each optionally with ":port".
//   - Loopback is NOT exempt by itself. Go's net/http/httpproxy always bypasses
//     localhost, which hides a local target from the operator's proxy; here a
//     loopback target is proxied unless NO_PROXY names it.
//
// Uppercase variables win over lowercase ones. The resolved Choice carries the
// variable each proxy came from, so plans, banners and errors can name it.
package proxyenv

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
)

// Source names where a proxy came from: SourceFlag, or the environment
// variable it was read from.
type Source = string

// SourceFlag is a proxy given with --proxy.
const SourceFlag Source = "--proxy"

// SourceVigoliumProxy is the environment fallback for --proxy; it proxies
// every request like the flag does.
const SourceVigoliumProxy Source = "VIGOLIUM_PROXY"

// Route is one proxy and where it came from.
type Route struct {
	URL    *url.URL
	Source Source
	// Everything marks --proxy (or VIGOLIUM_PROXY): every request goes
	// through it and NO_PROXY does not apply.
	Everything bool
}

// Redacted is the proxy URL with any password masked, for display.
func (r *Route) Redacted() string {
	if r == nil || r.URL == nil {
		return ""
	}
	return r.URL.Redacted()
}

// Choice is the resolved proxy configuration.
type Choice struct {
	// cli is --proxy; when set it is the only route.
	cli *Route
	// http, https and all are the environment's routes by scheme.
	http, https, all *Route
	// noProxy is the parsed NO_PROXY list, and noProxySource its variable.
	noProxy       []noProxyRule
	noProxySource string
	noProxyRaw    string
	// err is the first unparseable proxy value.
	err error
}

// Resolve builds the Choice for cliProxy (the --proxy value, "" for none) and
// the environment read through getenv (os.Getenv when nil).
func Resolve(cliProxy string, getenv func(string) string) Choice {
	if getenv == nil {
		getenv = os.Getenv
	}
	var c Choice
	if cli := strings.TrimSpace(cliProxy); cli != "" {
		// The CLI copies VIGOLIUM_PROXY into the flag's value when --proxy is
		// not typed; it behaves like --proxy, but is named for what it is.
		src := SourceFlag
		if v := strings.TrimSpace(getenv(SourceVigoliumProxy)); v != "" && v == cli {
			src = SourceVigoliumProxy
		}
		c.cli = c.parse(cli, src)
		if c.cli != nil {
			c.cli.Everything = true
		}
		return c
	}
	c.http = c.fromEnv(getenv, "HTTP_PROXY", "http_proxy")
	c.https = c.fromEnv(getenv, "HTTPS_PROXY", "https_proxy")
	c.all = c.fromEnv(getenv, "ALL_PROXY", "all_proxy")
	for _, k := range []string{"NO_PROXY", "no_proxy"} {
		if v := strings.TrimSpace(getenv(k)); v != "" {
			c.noProxy, c.noProxySource, c.noProxyRaw = parseNoProxy(v), k, v
			break
		}
	}
	return c
}

// FromEnvironment is Resolve(cliProxy, os.Getenv).
func FromEnvironment(cliProxy string) Choice { return Resolve(cliProxy, nil) }

func (c *Choice) fromEnv(getenv func(string) string, names ...string) *Route {
	for _, k := range names {
		if v := strings.TrimSpace(getenv(k)); v != "" {
			return c.parse(v, k)
		}
	}
	return nil
}

func (c *Choice) parse(raw string, source Source) *Route {
	u, err := parseProxyURL(raw)
	if err != nil {
		if c.err == nil {
			c.err = fmt.Errorf("%s: %w", source, err)
		}
		return nil
	}
	return &Route{URL: u, Source: source}
}

// parseProxyURL accepts "host:port" as http://host:port, as curl does.
func parseProxyURL(raw string) (*url.URL, error) {
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy URL %q: %w", raw, err)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("invalid proxy URL %q: no host", raw)
	}
	return u, nil
}

// Err is the first proxy value that could not be parsed, or nil.
func (c Choice) Err() error { return c.err }

// Any reports whether any request could be proxied.
func (c Choice) Any() bool { return c.cli != nil || c.http != nil || c.https != nil || c.all != nil }

// For returns the route a request to u takes, or nil to connect directly.
func (c Choice) For(u *url.URL) *Route {
	if u == nil {
		return nil
	}
	return c.ForHost(u.Scheme, u.Host)
}

// ForHost returns the route for a request with this scheme to host (host or
// host:port), or nil to connect directly.
func (c Choice) ForHost(scheme, host string) *Route {
	if c.cli != nil {
		return c.cli
	}
	var r *Route
	switch strings.ToLower(scheme) {
	case "https", "wss":
		r = c.https
	default:
		r = c.http
	}
	if r == nil {
		r = c.all
	}
	if r == nil || c.Bypass(scheme, host) {
		return nil
	}
	return r
}

// Bypass reports whether NO_PROXY exempts host (host or host:port) from an
// environment proxy. --proxy is never bypassed.
func (c Choice) Bypass(scheme, host string) bool {
	if c.cli != nil || len(c.noProxy) == 0 {
		return false
	}
	h, port := splitHostPort(scheme, host)
	ip := net.ParseIP(h)
	for _, rule := range c.noProxy {
		if rule.matches(h, ip, port) {
			return true
		}
	}
	return false
}

// Func is the http.Transport Proxy func for this choice, or nil when nothing
// is ever proxied (so the transport connects directly).
func (c Choice) Func() func(*http.Request) (*url.URL, error) {
	if !c.Any() {
		return nil
	}
	return func(req *http.Request) (*url.URL, error) {
		if r := c.For(req.URL); r != nil {
			return r.URL, nil
		}
		return nil, nil
	}
}

// Routes lists the configured routes for display: one per scheme the
// environment set, or the single --proxy route as scheme "*".
func (c Choice) Routes() []RouteView {
	if c.cli != nil {
		return []RouteView{{Scheme: "*", URL: c.cli.Redacted(), Source: c.cli.Source}}
	}
	var out []RouteView
	add := func(scheme string, r *Route) {
		if r != nil {
			out = append(out, RouteView{Scheme: scheme, URL: r.Redacted(), Source: r.Source})
		}
	}
	add("http", c.http)
	add("https", c.https)
	add("*", c.all)
	return out
}

// Proxies returns every distinct proxy a request could be sent through.
func (c Choice) Proxies() []*Route {
	var out []*Route
	seen := map[string]bool{}
	for _, r := range []*Route{c.cli, c.http, c.https, c.all} {
		if r != nil && !seen[r.URL.String()] {
			seen[r.URL.String()] = true
			out = append(out, r)
		}
	}
	return out
}

// RouteView is a route as plans and documents show it.
type RouteView struct {
	// Scheme is the request scheme the route applies to, "*" for every scheme.
	Scheme string `json:"scheme"`
	URL    string `json:"url"`
	Source string `json:"source"`
}

// NoProxy returns the NO_PROXY value in effect and the variable it came from
// ("", "" when none, or when --proxy makes it irrelevant).
func (c Choice) NoProxy() (value, source string) {
	if c.cli != nil {
		return "", ""
	}
	return c.noProxyRaw, c.noProxySource
}

// Describe renders the route a request to target takes, for a banner or an
// error: "http://127.0.0.1:8080 (from HTTPS_PROXY)", "direct (NO_PROXY)", or
// "" when no proxy is configured at all.
func (c Choice) Describe(target string) string {
	if !c.Any() {
		return ""
	}
	u, err := url.Parse(target)
	if err != nil || u.Host == "" {
		u = &url.URL{Scheme: "http", Host: target}
	}
	if r := c.For(u); r != nil {
		return fmt.Sprintf("%s (from %s)", r.Redacted(), r.Source)
	}
	if c.Bypass(u.Scheme, u.Host) {
		return "direct (" + c.noProxySource + ")"
	}
	return "direct"
}

// Summary renders every route on one line for a banner: "http://h:8080 for
// https (HTTPS_PROXY); NO_PROXY=localhost". "" when nothing is proxied.
func (c Choice) Summary() string {
	routes := c.Routes()
	if len(routes) == 0 {
		return ""
	}
	parts := make([]string, 0, len(routes)+1)
	for _, r := range routes {
		scope := "every request"
		if r.Scheme != "*" {
			scope = r.Scheme + " targets"
		} else if r.Source != SourceFlag && r.Source != SourceVigoliumProxy {
			scope = "targets with no scheme proxy"
		}
		parts = append(parts, fmt.Sprintf("%s for %s (%s)", r.URL, scope, r.Source))
	}
	if v, src := c.NoProxy(); v != "" {
		parts = append(parts, src+"="+v)
	}
	return strings.Join(parts, "; ")
}

// noProxyRule is one NO_PROXY entry.
type noProxyRule struct {
	all    bool
	ipNet  *net.IPNet
	ip     net.IP
	domain string // lowercased, without a leading dot
	port   string // "" matches every port
}

func parseNoProxy(v string) []noProxyRule {
	var out []noProxyRule
	for _, f := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' }) {
		f = strings.ToLower(strings.TrimSpace(f))
		if f == "" {
			continue
		}
		if f == "*" {
			out = append(out, noProxyRule{all: true})
			continue
		}
		if _, n, err := net.ParseCIDR(f); err == nil {
			out = append(out, noProxyRule{ipNet: n})
			continue
		}
		host, port := f, ""
		if h, p, err := net.SplitHostPort(f); err == nil {
			host, port = h, p
		}
		host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
		if ip := net.ParseIP(host); ip != nil {
			out = append(out, noProxyRule{ip: ip, port: port})
			continue
		}
		host = strings.TrimPrefix(strings.TrimPrefix(host, "*"), ".")
		if host != "" {
			out = append(out, noProxyRule{domain: host, port: port})
		}
	}
	return out
}

// matches reports whether the rule exempts host (ip is its parse, nil for a
// name) on port.
func (r noProxyRule) matches(host string, ip net.IP, port string) bool {
	if r.all {
		return true
	}
	if r.port != "" && r.port != port {
		return false
	}
	switch {
	case r.ipNet != nil:
		return ip != nil && r.ipNet.Contains(ip)
	case r.ip != nil:
		return ip != nil && r.ip.Equal(ip)
	default:
		return host == r.domain || strings.HasSuffix(host, "."+r.domain)
	}
}

// splitHostPort splits host[:port], filling the scheme's default port.
func splitHostPort(scheme, hostport string) (string, string) {
	host, port := hostport, ""
	if h, p, err := net.SplitHostPort(hostport); err == nil {
		host, port = h, p
	}
	host = strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(host, "["), "]"))
	if port == "" {
		port = "80"
		if strings.EqualFold(scheme, "https") || strings.EqualFold(scheme, "wss") {
			port = "443"
		}
	}
	return host, port
}
