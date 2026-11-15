package server

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"strings"
)

// DefaultIngestProxyHost is where the ingest proxy listens unless told
// otherwise. Loopback on purpose: an open forward proxy on a routable address
// lets anyone who can reach the port send traffic from this machine and write
// records into its database.
const DefaultIngestProxyHost = "127.0.0.1"

// proxyAuthRealm is the realm named in the 407 challenge.
const proxyAuthRealm = "vigolium"

// ProxyAuth gates the ingest proxy. Each configured check must pass: a client
// outside Allow is refused (403) before its credentials are looked at, and a
// client inside it still owes the Token when one is set (407). The zero value
// lets everyone through, which CheckProxyBind only permits on loopback.
type ProxyAuth struct {
	// Token is compared against the Proxy-Authorization credential: the
	// password of a Basic credential (any username) or a Bearer token.
	Token string
	// Allow lists the client networks the proxy accepts. Empty = any client.
	Allow []*net.IPNet
}

// NewProxyAuth builds a ProxyAuth from the token and the --proxy-allow
// entries, each a CIDR ("10.0.0.0/8") or a bare IP ("192.168.1.5").
func NewProxyAuth(token string, allow []string) (*ProxyAuth, error) {
	nets, err := ParseProxyAllow(allow)
	if err != nil {
		return nil, err
	}
	return &ProxyAuth{Token: token, Allow: nets}, nil
}

// ParseProxyAllow parses --proxy-allow entries. A bare IP becomes a host
// network (/32 or /128). Blank entries are skipped.
func ParseProxyAllow(entries []string) ([]*net.IPNet, error) {
	var out []*net.IPNet
	for _, raw := range entries {
		e := strings.TrimSpace(raw)
		if e == "" {
			continue
		}
		if strings.Contains(e, "/") {
			_, n, err := net.ParseCIDR(e)
			if err != nil {
				return nil, fmt.Errorf("invalid --proxy-allow %q: want a CIDR (10.0.0.0/8) or an IP", raw)
			}
			out = append(out, n)
			continue
		}
		ip := net.ParseIP(e)
		if ip == nil {
			return nil, fmt.Errorf("invalid --proxy-allow %q: want a CIDR (10.0.0.0/8) or an IP", raw)
		}
		bits := 128
		if ip4 := ip.To4(); ip4 != nil {
			ip, bits = ip4, 32
		}
		out = append(out, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
	}
	return out, nil
}

// Enabled reports whether any check is configured.
func (a *ProxyAuth) Enabled() bool {
	return a != nil && (a.Token != "" || len(a.Allow) > 0)
}

// IsLoopbackHost reports whether a bind host only accepts local connections.
// Empty, "0.0.0.0" and "::" bind every interface; a hostname other than
// localhost is treated as routable, since what it resolves to can change.
func IsLoopbackHost(host string) bool {
	h := strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(host), "["), "]")
	if strings.EqualFold(h, "localhost") {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// CheckProxyBind refuses a proxy that would listen on a routable address with
// no way to tell who is using it. The caller turns the error into a usage
// error (exit 2) before anything starts listening.
func CheckProxyBind(host string, auth *ProxyAuth) error {
	if IsLoopbackHost(host) || auth.Enabled() {
		return nil
	}
	shown := host
	if shown == "" {
		shown = "all interfaces"
	}
	return fmt.Errorf("refusing to bind the ingest proxy to %s without access control: "+
		"pass --proxy-token <secret> (or set server.ingest_proxy_token) and/or --proxy-allow <cidr>, "+
		"or keep the default --ingest-proxy-host %s", shown, DefaultIngestProxyHost)
}

// CheckAPIBind refuses an unauthenticated REST API on a routable address, the
// API's counterpart of CheckProxyBind: with no API key, everyone who can reach
// the port can read every recorded request and start scans. allowUnauth is the
// operator's explicit override.
func CheckAPIBind(host string, noAuth, allowUnauth bool) error {
	if !noAuth || allowUnauth || IsLoopbackHost(host) {
		return nil
	}
	shown := host
	if shown == "" || shown == "0.0.0.0" || shown == "::" || shown == "[::]" {
		shown = "all interfaces"
	}
	return fmt.Errorf("refusing to bind the REST API to %s without authentication (--no-auth): "+
		"drop --no-auth to require the API key, keep a loopback --host, "+
		"or pass --allow-unauthenticated-bind to expose it anyway", shown)
}

// authorize applies the configured checks to r. On refusal it has already
// written the response and returns false. On success it strips
// Proxy-Authorization, so the credential is neither forwarded upstream nor
// recorded with the transaction.
func (a *ProxyAuth) authorize(w http.ResponseWriter, r *http.Request) bool {
	if !a.Enabled() {
		r.Header.Del("Proxy-Authorization")
		return true
	}
	if len(a.Allow) > 0 && !a.allowed(r.RemoteAddr) {
		http.Error(w, "client address not allowed by --proxy-allow", http.StatusForbidden)
		return false
	}
	if a.Token != "" && !tokenMatches(proxyCredential(r.Header.Get("Proxy-Authorization")), a.Token) {
		w.Header().Set("Proxy-Authenticate", `Basic realm="`+proxyAuthRealm+`"`)
		http.Error(w, "proxy authentication required", http.StatusProxyAuthRequired)
		return false
	}
	r.Header.Del("Proxy-Authorization")
	return true
}

// allowed reports whether remoteAddr ("ip:port") falls in an allowed network.
func (a *ProxyAuth) allowed(remoteAddr string) bool {
	host := remoteAddr
	if h, _, err := net.SplitHostPort(remoteAddr); err == nil {
		host = h
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, n := range a.Allow {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// proxyCredential extracts the secret from a Proxy-Authorization value:
// the password of "Basic base64(user:password)" (a credential with no colon
// counts whole) or the token of "Bearer token". Anything else yields "".
func proxyCredential(header string) string {
	scheme, value, ok := strings.Cut(strings.TrimSpace(header), " ")
	if !ok {
		return ""
	}
	value = strings.TrimSpace(value)
	switch {
	case strings.EqualFold(scheme, "Bearer"):
		return value
	case strings.EqualFold(scheme, "Basic"):
		raw, err := base64.StdEncoding.DecodeString(value)
		if err != nil {
			return ""
		}
		if _, pass, found := strings.Cut(string(raw), ":"); found {
			return pass
		}
		return string(raw)
	}
	return ""
}

// tokenMatches compares in constant time. Both sides are hashed first so the
// comparison does not leak the token's length either.
func tokenMatches(got, want string) bool {
	if got == "" {
		return false
	}
	g := sha256.Sum256([]byte(got))
	w := sha256.Sum256([]byte(want))
	return subtle.ConstantTimeCompare(g[:], w[:]) == 1
}

// proxyAuthMode names the access control in force, for /server-info.
func proxyAuthMode(a *ProxyAuth) string {
	switch {
	case !a.Enabled():
		return "none"
	case a.Token != "" && len(a.Allow) > 0:
		return "token+allowlist"
	case a.Token != "":
		return "token"
	default:
		return "allowlist"
	}
}
