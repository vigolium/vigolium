package lab

import (
	"io"
	"log"
	"net/http"
	"sort"
	"sync"
	"time"
)

// Hit is one request a lab server received.
type Hit struct {
	Server   string
	Method   string
	Path     string
	RawQuery string
	Host     string
	Start    time.Time
	End      time.Time
	// Status is the HTTP status written, or StatusDropped / StatusClientGone.
	Status int
}

// Ledger records every request and connection the lab's servers received,
// and the per-server concurrency it saw. It is safe for concurrent use.
type Ledger struct {
	mu       sync.Mutex
	hits     []Hit
	inflight map[string]int
	open     map[*Hit]struct{}
	peak     map[string]int
	conns    map[string]int
}

// NewLedger returns an empty ledger.
func NewLedger() *Ledger {
	return &Ledger{inflight: map[string]int{}, open: map[*Hit]struct{}{}, peak: map[string]int{}, conns: map[string]int{}}
}

// begin notes a request arriving and returns the function that closes it.
func (l *Ledger) begin(server string, r *http.Request) func(status int) {
	h := &Hit{
		Server: server, Method: r.Method, Path: r.URL.Path, RawQuery: r.URL.RawQuery,
		Host: r.Host, Start: time.Now(),
	}
	l.mu.Lock()
	l.open[h] = struct{}{}
	l.inflight[server]++
	l.peak[server] = max(l.peak[server], l.inflight[server])
	l.mu.Unlock()
	return func(status int) {
		h.End, h.Status = time.Now(), status
		l.mu.Lock()
		l.inflight[server]--
		delete(l.open, h)
		l.hits = append(l.hits, *h)
		l.mu.Unlock()
	}
}

func (l *Ledger) recordConn(server string) {
	l.mu.Lock()
	l.conns[server]++
	l.mu.Unlock()
}

// each calls fn for every completed request to server ("" for all), in
// completion order, under the lock and without copying the history.
func (l *Ledger) each(server string, fn func(*Hit)) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for i := range l.hits {
		if server == "" || l.hits[i].Server == server {
			fn(&l.hits[i])
		}
	}
}

// Hits returns the completed requests to server ("" for every server), in
// completion order.
func (l *Ledger) Hits(server string) []Hit {
	var out []Hit
	l.each(server, func(h *Hit) { out = append(out, *h) })
	return out
}

// HitsSince returns every completed request from index i of the history on,
// for a reader that tails the ledger.
func (l *Ledger) HitsSince(i int) []Hit {
	l.mu.Lock()
	defer l.mu.Unlock()
	if i >= len(l.hits) {
		return nil
	}
	return append([]Hit(nil), l.hits[i:]...)
}

// Count is the number of completed requests to server ("" for all).
func (l *Ledger) Count(server string) int {
	n := 0
	l.each(server, func(*Hit) { n++ })
	return n
}

// Conns is the number of TCP connections a raw server accepted.
func (l *Ledger) Conns(server string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.conns[server]
}

// InFlight is the number of requests to server still being handled.
func (l *Ledger) InFlight(server string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.inflight[server]
}

// Open returns the requests still being handled, oldest first.
func (l *Ledger) Open() []Hit {
	l.mu.Lock()
	out := make([]Hit, 0, len(l.open))
	for h := range l.open {
		out = append(out, *h)
	}
	l.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Start.Before(out[j].Start) })
	return out
}

// PeakConcurrency is the most requests server was handling at once.
func (l *Ledger) PeakConcurrency(server string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.peak[server]
}

// MaxInWindow is the largest number of requests to server ("" for all) that
// started within any window-long interval — the observed burst rate.
func (l *Ledger) MaxInWindow(server string, window time.Duration) int {
	var starts []time.Time
	l.each(server, func(h *Hit) { starts = append(starts, h.Start) })
	sort.Slice(starts, func(i, j int) bool { return starts[i].Before(starts[j]) })
	best, lo := 0, 0
	for hi := range starts {
		for starts[hi].Sub(starts[lo]) >= window {
			lo++
		}
		best = max(best, hi-lo+1)
	}
	return best
}

// StatusCounts tallies server's hits by status.
func (l *Ledger) StatusCounts(server string) map[int]int {
	out := map[int]int{}
	l.each(server, func(h *Hit) { out[h.Status]++ })
	return out
}

// After returns server's hits that started at or after t.
func (l *Ledger) After(server string, t time.Time) []Hit {
	var out []Hit
	l.each(server, func(h *Hit) {
		if !h.Start.Before(t) {
			out = append(out, *h)
		}
	})
	return out
}

// Summary is a per-server digest for logs and the lab binary.
type Summary struct {
	Server   string      `json:"server"`
	Requests int         `json:"requests"`
	Conns    int         `json:"conns,omitempty"`
	Peak     int         `json:"peak_concurrency"`
	Status   map[int]int `json:"status"`
}

// Summaries digests every server the ledger has seen, sorted by name.
func (l *Ledger) Summaries() []Summary {
	l.mu.Lock()
	byName := map[string]*Summary{}
	get := func(name string) *Summary {
		s, ok := byName[name]
		if !ok {
			s = &Summary{Server: name, Status: map[int]int{}, Conns: l.conns[name], Peak: l.peak[name]}
			byName[name] = s
		}
		return s
	}
	for i := range l.hits {
		s := get(l.hits[i].Server)
		s.Requests++
		s.Status[l.hits[i].Status]++
	}
	for name := range l.conns {
		get(name)
	}
	l.mu.Unlock()
	out := make([]Summary, 0, len(byName))
	for _, s := range byName {
		out = append(out, *s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Server < out[j].Server })
	return out
}

func discardLogger() *log.Logger { return log.New(io.Discard, "", 0) }
