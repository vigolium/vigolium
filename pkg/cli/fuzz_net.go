package cli

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net"
	gohttp "net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/spf13/pflag"
	"github.com/vigolium/vigolium/pkg/bulkhttp"
	"github.com/vigolium/vigolium/pkg/fuzz"
	"github.com/vigolium/vigolium/pkg/input/formats/curl"
	"github.com/vigolium/vigolium/pkg/proxytarget"
)

// Curl-compatible network options. These are spelled with curl's long names so
// a command can be transliterated flag-for-flag; the short forms are left to
// vigolium's own meanings (-u is a record UUID, -i an input, -w a wordlist),
// since silently redefining them would break every existing invocation.
var (
	fuzzCookie         string
	fuzzUser           string
	fuzzUserAgent      string
	fuzzReferer        string
	fuzzInsecure       bool
	fuzzVerifyTLS      bool
	fuzzMaxRedirs      int
	fuzzConnectTimeout time.Duration
	fuzzMaxTime        time.Duration
	fuzzHTTPVersion    string
	fuzzResolve        []string
	fuzzClientCert     string
	fuzzClientKey      string
	fuzzCACert         string

	// Body builders, sharing curl's own assembly rules.
	fuzzDataRaw       []string
	fuzzDataBinary    []string
	fuzzDataURLEncode []string
	fuzzForm          []string
	fuzzFormString    []string
	fuzzAsGet         bool
	fuzzAsHead        bool

	// Session / auth carry-over, mirroring replay.
	fuzzAuthSession string
	fuzzSessionID   string
	fuzzNoCookies   bool
)

// registerFuzzNetFlags adds the curl-compatible request and network flags.
func registerFuzzNetFlags(f *pflag.FlagSet) {
	// Request identity (become headers).
	f.StringVar(&fuzzCookie, "cookie", "", "Cookie header value, curl's -b (e.g. 'a=1; b=2')")
	f.StringVar(&fuzzUser, "user", "", "Basic auth 'user:password', curl's -u")
	f.StringVar(&fuzzUserAgent, "user-agent", "", "User-Agent header, curl's -A")
	f.StringVar(&fuzzReferer, "referer", "", "Referer header, curl's -e")

	// Body construction, same semantics as curl's.
	f.StringArrayVar(&fuzzDataRaw, "data-raw", nil, "Body data with '@' taken literally (repeatable)")
	f.StringArrayVar(&fuzzDataBinary, "data-binary", nil, "Body data; '@file' is read verbatim, newlines kept (repeatable)")
	f.StringArrayVar(&fuzzDataURLEncode, "data-urlencode", nil, "URL-encoded body data; supports curl's name=value, @file and name@file forms (repeatable)")
	f.StringArrayVar(&fuzzForm, "form", nil, "multipart/form-data field 'name=value', 'name=@file' or 'name=<file' (repeatable)")
	f.StringArrayVar(&fuzzFormString, "form-string", nil, "multipart field whose value is never interpreted (repeatable)")
	f.BoolVar(&fuzzAsGet, "get", false, "Send the accumulated data as query parameters on a GET, curl's -G")
	f.BoolVar(&fuzzAsHead, "head", false, "Use HEAD, curl's -I")

	// Transport.
	f.BoolVar(&fuzzInsecure, "insecure", false, "Skip TLS verification (already the default; accepted for curl compatibility)")
	f.BoolVar(&fuzzVerifyTLS, "verify-tls", false, "Verify TLS certificates — the inverse of --insecure, and NOT the default")
	f.IntVar(&fuzzMaxRedirs, "max-redirs", 0, "Maximum redirects to follow (0 = Go's default of 10)")
	f.DurationVar(&fuzzConnectTimeout, "connect-timeout", 0, "TCP/TLS connect timeout (e.g. 5s)")
	f.DurationVar(&fuzzMaxTime, "max-time", 0, "Total per-request budget; alias for --timeout, curl's -m")
	f.StringVar(&fuzzHTTPVersion, "http-version", "", "Wire protocol: auto (default: HTTP/3, then HTTP/2, then HTTP/1.1), 1.1, 2, 3, or 3-only")
	f.StringArrayVar(&fuzzResolve, "resolve", nil, "Pin a host to an address, curl's --resolve host:port:addr (repeatable)")
	f.StringVar(&fuzzClientCert, "cert", "", "Client certificate file (PEM), curl's -E")
	f.StringVar(&fuzzClientKey, "key", "", "Client certificate private key file (PEM)")
	f.StringVar(&fuzzCACert, "cacert", "", "CA bundle used to verify the target (implies --verify-tls)")

	// Options curl has that vigolium already does by default. They are
	// accepted so a transliterated command doesn't have to be edited, and
	// bound to a throwaway destination rather than a package var, so nobody
	// later mistakes an intentional no-op for a flag someone forgot to wire.
	for _, inert := range []struct{ name, help string }{
		{"location", "Follow 30x redirects (already the default; use --no-redirects to stop)"},
		{"compressed", "Request a compressed response (already transparent)"},
		{"path-as-is", "Send the path byte-for-byte (already the case; see pkg/replay wire fidelity)"},
	} {
		f.BoolVar(new(bool), inert.name, false, inert.help+" — accepted for curl compatibility")
	}

	// Session / auth.
	f.StringVar(&fuzzAuthSession, "auth-session", "", "Auth session name whose headers are merged in (from 'vigolium auth list')")
	f.StringVar(&fuzzSessionID, "session-id", "", "Persist cookies across runs under ~/.vigolium/replay-jars/<id>.json")
	f.BoolVar(&fuzzNoCookies, "no-cookies", false, "Don't carry cookies (overrides --session-id)")

	// curl spells the HTTP version as two boolean flags; accept those too so a
	// transliterated command doesn't need editing.
	f.BoolVar(&fuzzHTTP11, "http1.1", false, "Force HTTP/1.1")
	f.BoolVar(&fuzzHTTP2, "http2", false, "Stay on TCP and use HTTP/2 where the target negotiates it (no HTTP/3)")
	f.BoolVar(&fuzzHTTP3, "http3", false, "Prefer HTTP/3, falling back to HTTP/2 or HTTP/1.1 (the default; curl's --http3)")
	f.BoolVar(&fuzzHTTP3Only, "http3-only", false, "Require HTTP/3 and fail when the target does not speak it (curl's --http3-only)")
}

var (
	fuzzHTTP11    bool
	fuzzHTTP2     bool
	fuzzHTTP3     bool
	fuzzHTTP3Only bool
)

// buildFuzzOverrides folds every request-shaping flag into one Overrides.
//
// Precedence runs lowest-to-highest: an auth session's stored headers, then
// the curl identity flags, then -H. That ordering lets an operator load a
// session and still override one of its headers for a single run, which is the
// common case when testing whether a header is what actually authorizes a
// request.
func buildFuzzOverrides(ctx context.Context, src *replaySource, fromPositionalURL bool) (fuzz.Overrides, error) {
	var o fuzz.Overrides

	if fuzzAsHead {
		o.Method = "HEAD"
	} else if fuzzMethod != "" {
		o.Method = fuzzMethod
	}

	sessionHeaders, err := fuzzAuthSessionHeaders(ctx, src)
	if err != nil {
		return o, err
	}
	o.Headers = append(o.Headers, sessionHeaders...)

	if fuzzUserAgent != "" {
		o.Headers = append(o.Headers, "User-Agent: "+fuzzUserAgent)
	}
	if fuzzReferer != "" {
		o.Headers = append(o.Headers, "Referer: "+fuzzReferer)
	}
	if fuzzCookie != "" {
		o.Headers = append(o.Headers, "Cookie: "+fuzzCookie)
	}
	if fuzzUser != "" {
		o.Headers = append(o.Headers, "Authorization: Basic "+basicAuthValue(fuzzUser))
	}

	body, contentType, err := buildFuzzBody(fromPositionalURL)
	if err != nil {
		return o, err
	}
	switch {
	case fuzzAsGet && body != "":
		// -G routes the data to the query string and leaves the body empty.
		o.QueryAppend = body
	case body != "":
		o.Body = body
		if contentType != "" {
			o.Headers = append(o.Headers, "Content-Type: "+contentType)
		}
		if o.Method == "" && !fuzzAsHead {
			o.Method = "POST"
		}
	}

	// -H last so it wins over everything synthesized above.
	o.Headers = append(o.Headers, fuzzHeaders...)
	return o, nil
}

// buildFuzzBody assembles the body from the curl data/form flags, reusing the
// curl package's own assembly so --data-urlencode and --form behave identically
// whether they arrive as `fuzz` flags or inside a pasted curl command.
//
// -d is skipped when the request came from a positional URL, because
// buildRequestFromFlags already folded it in there.
func buildFuzzBody(fromPositionalURL bool) (body, contentType string, err error) {
	var parts []string

	if fuzzData != "" && !fromPositionalURL {
		v, derr := curl.ResolveData(fuzzData, curl.DataAscii)
		if derr != nil {
			return "", "", derr
		}
		parts = append(parts, v)
	}
	for _, spec := range []struct {
		values []string
		kind   curl.DataKind
	}{
		{fuzzDataRaw, curl.DataRaw},
		{fuzzDataBinary, curl.DataBinary},
		{fuzzDataURLEncode, curl.DataURLEncode},
	} {
		for _, v := range spec.values {
			resolved, derr := curl.ResolveData(v, spec.kind)
			if derr != nil {
				return "", "", derr
			}
			parts = append(parts, resolved)
		}
	}

	if len(fuzzForm) > 0 || len(fuzzFormString) > 0 {
		if len(parts) > 0 {
			return "", "", usageErrorf("--form cannot be combined with the --data flags (curl builds one body, not both)")
		}
		body, contentType = curl.BuildMultipartBody(fuzzForm, fuzzFormString)
		return body, contentType, nil
	}

	if len(parts) == 0 {
		return "", "", nil
	}
	body = strings.Join(parts, "&")
	return body, curl.GuessContentType(body), nil
}

// fuzzAuthSessionHeaders resolves --auth-session into header overrides for the
// request's host.
func fuzzAuthSessionHeaders(ctx context.Context, src *replaySource) ([]string, error) {
	if fuzzAuthSession == "" {
		return nil, nil
	}
	overlay, err := resolveAuthSessionHeaders(ctx, fuzzAuthSession, src)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(overlay))
	for name := range overlay {
		names = append(names, name)
	}
	sort.Strings(names) // deterministic order so runs are reproducible
	out := make([]string, 0, len(names))
	for _, name := range names {
		out = append(out, name+": "+overlay[name])
	}
	return out, nil
}

// resolveFuzzTimeout reconciles --timeout with curl's --max-time; the smaller
// non-zero value wins so neither can silently extend the other.
func resolveFuzzTimeout() time.Duration {
	switch {
	case fuzzMaxTime > 0 && fuzzTimeout > 0:
		if fuzzMaxTime < fuzzTimeout {
			return fuzzMaxTime
		}
		return fuzzTimeout
	case fuzzMaxTime > 0:
		return fuzzMaxTime
	default:
		return fuzzTimeout
	}
}

// fuzzHTTPVersionSetting folds curl's --http1.1/--http2/--http3/--http3-only
// booleans and the explicit --http-version into one protocol mode. With none
// of them the mode is auto: HTTP/3 where the target proves it, else HTTP/2
// where ALPN selects it, else HTTP/1.1.
func fuzzHTTPVersionSetting() (bulkhttp.Mode, error) {
	var set []string
	for _, b := range []struct {
		on   bool
		name string
	}{{fuzzHTTP11, "--http1.1"}, {fuzzHTTP2, "--http2"}, {fuzzHTTP3, "--http3"}, {fuzzHTTP3Only, "--http3-only"}} {
		if b.on {
			set = append(set, b.name)
		}
	}
	if len(set) > 1 {
		return "", usageErrorf("%s are mutually exclusive", strings.Join(set, " and "))
	}
	switch {
	case fuzzHTTP11:
		return bulkhttp.ModeHTTP1, nil
	case fuzzHTTP2:
		return bulkhttp.ModeHTTP2, nil
	case fuzzHTTP3:
		return bulkhttp.ModeAuto, nil
	case fuzzHTTP3Only:
		return bulkhttp.ModeHTTP3, nil
	}
	v := strings.ToLower(strings.TrimSpace(fuzzHTTPVersion))
	switch v {
	case "3-only", "http3-only", "h3-only":
		return bulkhttp.ModeHTTP3, nil
	case "3", "http3", "h3":
		// curl's --http-version 3 prefers HTTP/3 and still falls back.
		return bulkhttp.ModeAuto, nil
	case "2.0":
		return bulkhttp.ModeHTTP2, nil
	}
	mode, err := bulkhttp.ParseMode(v)
	if err != nil {
		return "", usageErrorf("--http-version %q: want auto, 1.1, 2, 3 or 3-only", fuzzHTTPVersion)
	}
	return mode, nil
}

// buildFuzzClient constructs the HTTP client for a fuzz run from the
// curl-compatible transport flags, starting from replay's client (which
// carries the --proxy routing and the permissive TLS default) and layering the
// explicit options on top.
//
// mode is the run's protocol policy. Under bulkhttp.ModeHTTP1 the client is a
// plain HTTP/1.1 transport, as fuzz has always used; otherwise the HTTP/1.1
// transport becomes the template of a bulkhttp.Transport (returned too, for
// Prepare and Close), which pins the target to HTTP/3, HTTP/2 or HTTP/1.1.
func buildFuzzClient(cookies gohttp.CookieJar, mode bulkhttp.Mode) (*gohttp.Client, *bulkhttp.Transport, error) {
	client := newReplayClient(nil, resolveFuzzTimeout())
	client.Jar = cookies

	base, ok := proxytarget.Base(client.Transport)
	if !ok {
		return client, nil, nil
	}
	transport := base.Clone()

	tlsCfg := transport.TLSClientConfig
	if tlsCfg == nil {
		tlsCfg = &tls.Config{} //nolint:gosec // verification is configured just below
	}

	// Verification is off by default (staging and self-signed targets are the
	// norm); --verify-tls and --cacert are the ways to turn it on.
	tlsCfg.InsecureSkipVerify = !fuzzVerifyTLS && fuzzCACert == "" //nolint:gosec // deliberate default for a scanner

	if fuzzCACert != "" {
		pem, err := os.ReadFile(fuzzCACert)
		if err != nil {
			return nil, nil, fmt.Errorf("read --cacert %q: %w", fuzzCACert, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			//vigolium:not-usage decided from file contents, after I/O
			return nil, nil, fmt.Errorf("--cacert %q: no certificates found", fuzzCACert)
		}
		tlsCfg.RootCAs = pool
	}

	if fuzzClientCert != "" {
		keyFile := fuzzClientKey
		if keyFile == "" {
			// curl allows the key to live in the same PEM as the cert.
			keyFile = fuzzClientCert
		}
		cert, err := tls.LoadX509KeyPair(fuzzClientCert, keyFile)
		if err != nil {
			return nil, nil, fmt.Errorf("load --cert/--key: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	} else if fuzzClientKey != "" {
		return nil, nil, usageErrorf("--key requires --cert")
	}
	transport.TLSClientConfig = tlsCfg

	// HTTP/1.1 here: an empty non-nil TLSNextProto map is Go's documented way
	// to disable the automatic HTTP/2 upgrade. bulkhttp derives its HTTP/2 and
	// HTTP/3 transports from this one when the mode allows them.
	transport.ForceAttemptHTTP2 = false
	transport.TLSNextProto = map[string]func(string, *tls.Conn) gohttp.RoundTripper{}

	dialer := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
	if fuzzConnectTimeout > 0 {
		dialer.Timeout = fuzzConnectTimeout
	}
	overrides, err := parseResolveOverrides(fuzzResolve)
	if err != nil {
		return nil, nil, err
	}
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if target, ok := overrides[strings.ToLower(addr)]; ok {
			addr = target
		}
		return dialer.DialContext(ctx, network, addr)
	}

	// Go's default MaxIdleConnsPerHost is 2. A fuzzer points all of its
	// concurrency at ONE host, so at -c 10 eight of every ten connections were
	// closed instead of pooled and the next send paid a fresh TCP+TLS
	// handshake — several RTTs on the large majority of requests.
	if fuzzConcurrency > transport.MaxIdleConnsPerHost {
		transport.MaxIdleConnsPerHost = fuzzConcurrency
		transport.MaxIdleConns = fuzzConcurrency * 2
	}
	// Re-wrapped so a fuzzed or retargeted Host header still reaches an HTTP
	// proxy addressed to the destination's host:port (see pkg/proxytarget);
	// bulkhttp applies the same wrapper to its own TCP transports.
	var bulk *bulkhttp.Transport
	if mode == bulkhttp.ModeHTTP1 {
		client.Transport = proxytarget.Wrap(transport)
	} else {
		bulk = bulkhttp.New(bulkhttp.Config{
			Base: transport,
			Mode: mode,
			// --resolve pins the HTTP/3 dial too, not just TCP.
			ResolveAddr: func(hostPort string) string { return overrides[strings.ToLower(hostPort)] },
		})
		client.Transport = bulk
	}

	if fuzzMaxRedirs > 0 {
		limit := fuzzMaxRedirs
		client.CheckRedirect = func(_ *gohttp.Request, via []*gohttp.Request) error {
			if len(via) >= limit {
				return fmt.Errorf("stopped after %d redirects", limit)
			}
			return nil
		}
	}
	return client, bulk, nil
}

// parseResolveOverrides turns curl's "host:port:addr" entries into an
// addr→addr dial map. curl also accepts a leading "+" (meaning the entry
// expires) and "*" as a wildcard host; the "+" is accepted and ignored.
func parseResolveOverrides(entries []string) (map[string]string, error) {
	if len(entries) == 0 {
		return nil, nil
	}
	out := make(map[string]string, len(entries))
	for _, e := range entries {
		spec := strings.TrimPrefix(strings.TrimSpace(e), "+")
		parts := strings.Split(spec, ":")
		if len(parts) < 3 {
			return nil, usageErrorf("--resolve %q: want host:port:address", e)
		}
		host, port := parts[0], parts[1]
		addr := strings.Join(parts[2:], ":") // IPv6 literals carry colons
		addr = strings.Trim(addr, "[]")
		if host == "" || port == "" || addr == "" {
			return nil, usageErrorf("--resolve %q: want host:port:address", e)
		}
		out[strings.ToLower(net.JoinHostPort(host, port))] = net.JoinHostPort(addr, port)
	}
	return out, nil
}

// fuzzCookieJar opens the persistent jar for --session-id, returning a nil jar
// (and a no-op save) when cookies aren't being carried. Cookies matter here
// because a fuzz run is hundreds of requests against a session that a single
// rotation would otherwise invalidate halfway through.
func fuzzCookieJar() (gohttp.CookieJar, int, func(), error) {
	if fuzzNoCookies || fuzzSessionID == "" {
		return nil, 0, func() {}, nil
	}
	pj, loaded, err := openSessionJar(fuzzSessionID)
	if err != nil {
		return nil, 0, func() {}, err
	}
	return pj, loaded, func() { saveReplayJar(pj) }, nil
}

// validateFuzzNetFlags rejects contradictory transport options up front, so a
// long run doesn't start before an unusable combination is noticed.
func validateFuzzNetFlags() error {
	if fuzzVerifyTLS && fuzzInsecure {
		return usageErrorf("--insecure and --verify-tls are mutually exclusive")
	}
	if _, err := fuzzHTTPVersionSetting(); err != nil {
		return err
	}
	if _, err := parseResolveOverrides(fuzzResolve); err != nil {
		return err
	}
	if fuzzAsGet && fuzzAsHead {
		return usageErrorf("--get and --head are mutually exclusive")
	}
	return nil
}

// basicAuthValue encodes a curl-style "user:password" for an Authorization
// header.
func basicAuthValue(userPass string) string {
	return base64.StdEncoding.EncodeToString([]byte(userPass))
}
