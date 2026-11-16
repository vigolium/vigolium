// Package lab is a programmable, in-process target for exercising the scanner
// end to end: planted vulnerabilities with benign twins, hostile servers that
// misbehave the way real targets do, faults that can be switched on mid-run,
// and a ledger that records every request each server received.
//
// It is an ordinary package so the expectation e2e kit (test/e2e-expect) and
// the standalone lab binary (test/tools/lab) share it. The benign fixtures it
// reuses come from pkg/modules/modtest.
package lab

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// Lab owns every server it started and the ledger they share.
type Lab struct {
	Ledger *Ledger
	// PortBase, when non-zero, makes servers listen on consecutive ports
	// from it (in start order) instead of random ones — for the standalone
	// lab binary, where stable URLs matter.
	PortBase int
	nextPort int

	mu      sync.Mutex
	servers []*Server
	raws    []*RawServer
	// done is closed by Close so handlers that park forever (Hang, Tarpit)
	// return and httptest.Server.Close does not wait on them.
	done      chan struct{}
	closeOnce sync.Once
}

// New returns an empty lab.
func New() *Lab {
	return &Lab{Ledger: NewLedger(), done: make(chan struct{})}
}

// Close stops every server. Safe to call more than once.
func (l *Lab) Close() {
	l.closeOnce.Do(func() {
		close(l.done)
		l.mu.Lock()
		servers, raws := l.servers, l.raws
		l.mu.Unlock()
		for _, s := range servers {
			s.srv.CloseClientConnections()
			s.srv.Close()
		}
		for _, r := range raws {
			r.Close()
		}
	})
}

// Server is one HTTP(S) listener on 127.0.0.1.
type Server struct {
	Name string
	// URL is the base URL on 127.0.0.1 (no trailing slash).
	URL string
	// Port is the listening port.
	Port   int
	Faults *Faults

	srv *httptest.Server
}

// Origin returns the server's base URL with the given hostname in place of
// 127.0.0.1 (e.g. "localhost"), which is how a test addresses the same
// listener under a name the scan's scope does not cover.
func (s *Server) Origin(hostname string) string {
	u, _ := url.Parse(s.URL)
	return u.Scheme + "://" + net.JoinHostPort(hostname, fmt.Sprint(s.Port))
}

// Serve starts a plain-HTTP server named name. Every request is recorded in
// the ledger under name and passes through the server's fault switches.
func (l *Lab) Serve(name string, h http.Handler) *Server {
	return l.start(name, h, false)
}

// ServeTLS starts an HTTPS server with httptest's self-signed certificate.
func (l *Lab) ServeTLS(name string, h http.Handler) *Server {
	return l.start(name, h, true)
}

func (l *Lab) start(name string, h http.Handler, useTLS bool) *Server {
	s := &Server{Name: name, Faults: &Faults{}}
	srv := httptest.NewUnstartedServer(l.wrap(s, h))
	if ln := l.fixedListener(); ln != nil {
		_ = srv.Listener.Close()
		srv.Listener = ln
	}
	// A hostile handler must not be able to wedge the listener for other
	// connections; keep the defaults generous but bounded.
	srv.Config.ReadHeaderTimeout = 10 * time.Second
	srv.Config.ErrorLog = discardLogger()
	if useTLS {
		srv.TLS = &tls.Config{MinVersion: tls.VersionTLS12}
		srv.StartTLS()
	} else {
		srv.Start()
	}
	s.srv = srv
	s.URL = srv.URL
	s.Port = srv.Listener.Addr().(*net.TCPAddr).Port
	l.mu.Lock()
	l.servers = append(l.servers, s)
	l.mu.Unlock()
	return s
}

// Servers lists every HTTP server, sorted by name.
func (l *Lab) Servers() []*Server {
	l.mu.Lock()
	out := append([]*Server(nil), l.servers...)
	l.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// wrap records the request in the ledger and applies the server's faults
// before the handler sees it.
func (l *Lab) wrap(s *Server, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		end := l.Ledger.begin(s.Name, r)
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		defer func() {
			// A handler that returned without answering either lost its
			// client (Hang, a timed-out tarpit) or answered 200 implicitly.
			if !rec.wrote && r.Context().Err() != nil {
				rec.status = StatusClientGone
			}
			end(rec.status)
		}()

		if s.Faults.down.Load() {
			dropConnection(rec)
			return
		}
		if d := time.Duration(s.Faults.latency.Load()); d > 0 {
			select {
			case <-time.After(d):
			case <-r.Context().Done():
				return
			case <-l.done:
				return
			}
		}
		if code := int(s.Faults.status.Load()); code != 0 {
			rec.WriteHeader(code)
			_, _ = fmt.Fprintf(rec, "fault injected: %d\n", code)
			return
		}
		h.ServeHTTP(rec, r.WithContext(withLab(r.Context(), l)))
	})
}

// Faults are switches a test flips while a scan is running.
type Faults struct {
	down    atomic.Bool
	latency atomic.Int64
	status  atomic.Int64
}

// SetDown makes every request get its connection closed without a response
// (true) or restores normal service (false).
func (f *Faults) SetDown(down bool) { f.down.Store(down) }

// SetLatency delays every response by d (0 clears it).
func (f *Faults) SetLatency(d time.Duration) { f.latency.Store(int64(d)) }

// SetStatus answers every request with code (0 clears it).
func (f *Faults) SetStatus(code int) { f.status.Store(int64(code)) }

// Pseudo-statuses the ledger records for requests that got no HTTP status.
const (
	// StatusDropped: the lab closed the connection without answering.
	StatusDropped = -1
	// StatusClientGone: the client hung up before the handler answered.
	StatusClientGone = -2
)

// dropConnection closes the underlying connection without writing a
// response — what a crashed backend or an aggressive middlebox looks like.
func dropConnection(w http.ResponseWriter) {
	if rec, ok := w.(*statusRecorder); ok {
		rec.status, rec.wrote = StatusDropped, true
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		panic(http.ErrAbortHandler)
	}
	conn, _, err := hj.Hijack()
	if err != nil {
		return
	}
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetLinger(0) // RST rather than FIN
	}
	_ = conn.Close()
}

type statusRecorder struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (r *statusRecorder) WriteHeader(code int) {
	if !r.wrote {
		r.status, r.wrote = code, true
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	r.wrote = true
	return r.ResponseWriter.Write(b)
}

func (r *statusRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (r *statusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := r.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, http.ErrNotSupported
	}
	r.wrote = true
	return hj.Hijack()
}

type labKey struct{}

func withLab(ctx context.Context, l *Lab) context.Context { return context.WithValue(ctx, labKey{}, l) }

// labDone returns the owning lab's shutdown channel for a request, or a nil
// channel (blocks forever) outside a lab.
func labDone(r *http.Request) <-chan struct{} {
	if l, ok := r.Context().Value(labKey{}).(*Lab); ok {
		return l.done
	}
	return nil
}

// RawServer is a TCP listener that speaks whatever its handler writes —
// for ports that accept a connection and then do not speak HTTP.
type RawServer struct {
	Name string
	Addr string
	// URL is http://Addr, what a scanner would be pointed at.
	URL string

	ln    net.Listener
	wg    sync.WaitGroup
	conns sync.Map
}

// ServeRaw starts a TCP listener whose connections are handed to fn. Each
// accepted connection is counted in the ledger under name.
func (l *Lab) ServeRaw(name string, fn func(net.Conn)) *RawServer {
	ln := l.fixedListener()
	if ln == nil {
		var err error
		if ln, err = net.Listen("tcp", "127.0.0.1:0"); err != nil {
			panic(fmt.Sprintf("lab: listen: %v", err))
		}
	}
	rs := &RawServer{Name: name, Addr: ln.Addr().String(), URL: "http://" + ln.Addr().String(), ln: ln}
	rs.wg.Add(1)
	go func() {
		defer rs.wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			l.Ledger.recordConn(name)
			rs.conns.Store(c, struct{}{})
			rs.wg.Add(1)
			go func() {
				defer rs.wg.Done()
				defer rs.conns.Delete(c)
				defer func() { _ = c.Close() }()
				fn(c)
			}()
		}
	}()
	l.mu.Lock()
	l.raws = append(l.raws, rs)
	l.mu.Unlock()
	return rs
}

// Close stops accepting, closes live connections and waits for handlers.
// Lab.Close calls it once.
func (rs *RawServer) Close() {
	_ = rs.ln.Close()
	rs.conns.Range(func(k, _ any) bool {
		_ = k.(net.Conn).Close()
		return true
	})
	rs.wg.Wait()
}

// fixedListener returns a listener on the next PortBase port, or nil when
// PortBase is unset.
func (l *Lab) fixedListener() net.Listener {
	if l.PortBase == 0 {
		return nil
	}
	l.mu.Lock()
	port := l.PortBase + l.nextPort
	l.nextPort++
	l.mu.Unlock()
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		panic(fmt.Sprintf("lab: listen on %d: %v", port, err))
	}
	return ln
}

// FreePort returns a 127.0.0.1 port that was free a moment ago: it was bound
// and released.
func FreePort() int {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(fmt.Sprintf("lab: listen: %v", err))
	}
	defer func() { _ = ln.Close() }()
	return ln.Addr().(*net.TCPAddr).Port
}

// DeadURL returns an http URL on 127.0.0.1 whose port refuses connections.
func DeadURL() string { return fmt.Sprintf("http://127.0.0.1:%d", FreePort()) }
