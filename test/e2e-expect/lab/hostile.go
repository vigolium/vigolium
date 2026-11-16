package lab

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// Benign servers shared with the module-level benign sweep (pkg/modules/modtest);
// modtest.BenignFixtures has the rest (WAF, soft-404, random content, 429).
var (
	SafeEcho = modtest.SafeEcho
	SlowHost = modtest.SlowHost
)

// Throttled serves inner but answers 429 with Retry-After once more than
// burst requests arrive within window — a token-bucket limiter that recovers,
// unlike modtest.RateLimit429 which never does. A scanner that keeps hammering
// through it shows up as a high 429 share in the ledger.
func Throttled(inner http.Handler, burst int, window time.Duration) http.Handler {
	var (
		mu     sync.Mutex
		starts []time.Time
	)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		now := time.Now()
		mu.Lock()
		kept := starts[:0]
		for _, t := range starts {
			if now.Sub(t) < window {
				kept = append(kept, t)
			}
		}
		starts = kept
		over := len(starts) >= burst
		if !over {
			starts = append(starts, now)
		}
		mu.Unlock()
		if over {
			w.Header().Set("Retry-After", strconv.Itoa(max(1, int(window/time.Second))))
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error":"rate limited"}`))
			return
		}
		inner.ServeHTTP(w, r)
	})
}

// Flaky drops the connection on every nth request and serves inner otherwise.
func Flaky(inner http.Handler, n int64) http.Handler {
	var c atomic.Int64
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c.Add(1)%n == 0 {
			dropConnection(w)
			return
		}
		inner.ServeHTTP(w, r)
	})
}

// DropWhen drops the connection for every request pred selects (retries
// included, so a client cannot paper over it) and serves inner otherwise.
func DropWhen(inner http.Handler, pred func(*http.Request) bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if pred(r) {
			dropConnection(w)
			return
		}
		inner.ServeHTTP(w, r)
	})
}

// Hang never answers: it holds the request open until the client gives up
// or the lab shuts down.
func Hang() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-labDone(r):
		}
	})
}

// Tarpit sends a 200 and a valid HTML prefix, then dribbles one byte every
// interval forever — headers arrive at once, the body never finishes.
func Tarpit(interval time.Duration) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><body>"))
		f, _ := w.(http.Flusher)
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			if f != nil {
				f.Flush()
			}
			select {
			case <-r.Context().Done():
				return
			case <-labDone(r):
				return
			case <-t.C:
				if _, err := w.Write([]byte(".")); err != nil {
					return
				}
			}
		}
	})
}

// HugeBody streams size bytes of HTML-ish filler, without Content-Length.
func HugeBody(size int64) http.Handler {
	chunk := bytes.Repeat([]byte("<p>lorem ipsum dolor sit amet</p>\n"), 2048)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		for sent := int64(0); sent < size; {
			n := min(int64(len(chunk)), size-sent)
			if _, err := w.Write(chunk[:n]); err != nil {
				return
			}
			sent += n
		}
	})
}

// gzipBombs caches each GzipBomb body by inflated size for the process:
// compressing 512 MiB takes seconds, and every Minefield wants the same one.
var gzipBombs sync.Map // int64 → func() []byte

func gzipBombBody(inflated int64) []byte {
	f, _ := gzipBombs.LoadOrStore(inflated, sync.OnceValue(func() []byte {
		var buf bytes.Buffer
		zw, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
		zero := make([]byte, 1<<20)
		for left := inflated; left > 0; left -= int64(len(zero)) {
			_, _ = zw.Write(zero[:min(int64(len(zero)), left)])
		}
		_ = zw.Close()
		return buf.Bytes()
	}))
	return f.(func() []byte)()
}

// GzipBomb answers with a gzip-encoded body that inflates to inflated bytes
// of zeros (a few hundred KiB on the wire for 512 MiB inflated).
func GzipBomb(inflated int64) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := gzipBombBody(inflated)
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		_, _ = w.Write(body)
	})
}

// BadChunked answers with a chunked body whose chunk-size line is not hex
// and whose stream is then cut.
func BadChunked() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "no hijack", http.StatusInternalServerError)
			return
		}
		conn, buf, err := hj.Hijack()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_, _ = buf.WriteString("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nTransfer-Encoding: chunked\r\n\r\n" +
			"5\r\n<html\r\nzz-not-hex\r\ngarbage")
		_ = buf.Flush()
	})
}

// LyingLength declares a Content-Length longer than the body it sends, then
// closes the connection.
func LyingLength() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			return
		}
		conn, buf, err := hj.Hijack()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_, _ = buf.WriteString("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 100000\r\n\r\n<html><body>short")
		_ = buf.Flush()
	})
}

// RedirectLoop redirects every request to the same path with a counter
// appended, forever.
func RedirectLoop() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, _ := strconv.Atoi(r.URL.Query().Get("hop"))
		q := r.URL.Query()
		q.Set("hop", strconv.Itoa(n+1))
		http.Redirect(w, r, r.URL.Path+"?"+q.Encode(), http.StatusFound)
	})
}

// mines are Minefield's hostile endpoints, in link order.
var mines = []struct {
	path string
	h    func() http.Handler
}{
	{"/mine/huge", func() http.Handler { return HugeBody(64 << 20) }},
	{"/mine/gzip", func() http.Handler { return GzipBomb(512 << 20) }},
	{"/mine/chunked", BadChunked},
	{"/mine/short", LyingLength},
	{"/mine/loop", RedirectLoop},
	{"/mine/hang", Hang},
	{"/mine/tarpit", func() http.Handler { return Tarpit(time.Second) }},
	{"/mine/reset", func() http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { dropConnection(w) })
	}},
	{"/mine/500", func() http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "boom", http.StatusInternalServerError) })
	}},
}

// MinePaths lists Minefield's hostile endpoints.
func MinePaths() []string {
	out := make([]string, len(mines))
	for i, m := range mines {
		out[i] = m.path
	}
	return out
}

// Minefield is VulnApp plus a /mine/ subtree of hostile endpoints, each with
// a query parameter so active modules attack it. The index links to every
// mine, so discovery and seeding reach them.
func Minefield(opts VulnAppOptions) http.Handler {
	mux := http.NewServeMux()
	opts.ExtraLinks = slices.Clip(opts.ExtraLinks) // never append into the caller's array
	for _, m := range mines {
		mux.Handle(m.path, m.h())
		opts.ExtraLinks = append(opts.ExtraLinks, m.path+"?id=1")
	}
	mux.Handle("/", VulnApp(opts))
	return mux
}

// Raw TCP behaviours for ServeRaw.

// SSHBanner writes an SSH identification string and closes — a non-HTTP
// service on a port a target list says is web.
func SSHBanner(c net.Conn) {
	_, _ = c.Write([]byte("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n"))
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _ = c.Read(make([]byte, 512))
}

// Garbage writes binary noise and closes.
func Garbage(c net.Conn) {
	_, _ = c.Write([]byte("\x00\xff\x13\x37garbage\r\n\r\n\x00\x00not http at all\x7f"))
}

// Silent accepts and never writes, holding the connection until the peer
// hangs up or the server closes.
func Silent(c net.Conn) {
	buf := make([]byte, 4096)
	for {
		if _, err := c.Read(buf); err != nil {
			return
		}
	}
}

// ReverseProxy forwards every request to target (e.g. a Docker app), so a
// live target's traffic goes through the lab's ledger and fault switches like
// any lab server's. Bodies stream through; nothing is buffered.
func ReverseProxy(target string) http.Handler {
	u, err := url.Parse(target)
	if err != nil {
		panic(fmt.Sprintf("lab: proxy target %q: %v", target, err))
	}
	rp := httputil.NewSingleHostReverseProxy(u)
	rp.ErrorLog = discardLogger()
	rp.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, err error) {
		http.Error(w, "lab proxy: upstream: "+err.Error(), http.StatusBadGateway)
	}
	return rp
}
