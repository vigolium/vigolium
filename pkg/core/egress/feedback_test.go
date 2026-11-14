package egress

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/core/ratelimit"
)

func newAdaptiveHosts(t *testing.T, perHost int, wafAutoArm bool) *ratelimit.HostRateLimiter {
	t.Helper()
	cfg := ratelimit.DefaultHostRateLimiterConfig()
	cfg.MaxPerHost = perHost
	cfg.AcquireTimeout = 5 * time.Second
	cfg.Adaptive = !wafAutoArm
	cfg.WafAutoArm = wafAutoArm
	h := ratelimit.NewHostRateLimiter(cfg)
	t.Cleanup(func() { _ = h.Close() })
	return h
}

func hostOf(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u.Hostname()
}

type stubBlocks struct{ marker string }

func (stubBlocks) IsBlockStatus(status int) bool { return status == http.StatusForbidden }
func (s stubBlocks) IsBlock(_ int, _ http.Header, body []byte) bool {
	return strings.Contains(string(body), s.marker)
}

// The plain RoundTripper never reported a response, so a throttling host was
// never backed off on that path; the feedback variant must report a 429.
func TestFeedbackRoundTripperBacksOffOnThrottle(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()
	host := hostOf(t, srv.URL)

	for _, tc := range []struct {
		name     string
		feedback bool
		backoff  bool
	}{
		{"plain round tripper reports nothing", false, false},
		{"feedback round tripper backs off", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hosts := newAdaptiveHosts(t, 20, false)
			g := New(Config{Hosts: hosts})
			rt := g.RoundTripper(nil, LaneNormal)
			if tc.feedback {
				rt = g.FeedbackRoundTripper(nil, LaneNormal, nil)
			}
			resp, err := (&http.Client{Transport: rt}).Get(srv.URL)
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()
			limit, _ := hosts.CurrentLimit(host)
			if backedOff := limit < 20; backedOff != tc.backoff {
				t.Errorf("limit after a 429 = %d (backed off = %v), want backed off = %v", limit, backedOff, tc.backoff)
			}
		})
	}
}

// A WAF block page arms WAF-auto-arm back-off, and classifying it must leave
// the body intact for the caller.
func TestFeedbackRoundTripperClassifiesBlocksAndKeepsBody(t *testing.T) {
	page := "<html>request blocked by edge " + strings.Repeat("x", 2*blockPeekBytes) + "</html>"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, page)
	}))
	defer srv.Close()
	host := hostOf(t, srv.URL)

	hosts := newAdaptiveHosts(t, 20, true)
	g := New(Config{Hosts: hosts})
	client := &http.Client{Transport: g.FeedbackRoundTripper(nil, LaneNormal, stubBlocks{marker: "request blocked"})}
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != page {
		t.Errorf("body after classification is %d bytes, want the original %d", len(body), len(page))
	}
	if limit, _ := hosts.CurrentLimit(host); limit >= 20 {
		t.Errorf("limit after a classified block = %d, want backed off below 20", limit)
	}
}

// A request the caller cancelled says nothing about the host; a client
// timeout is the host failing to answer and counts as distress (MISS-23).
func TestFeedbackRoundTripperIgnoresCancelled(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(release)
	host := hostOf(t, srv.URL)

	hosts := newAdaptiveHosts(t, 20, false)
	g := New(Config{Hosts: hosts})
	client := &http.Client{Transport: g.FeedbackRoundTripper(nil, LaneNormal, nil)}
	ctx, cancel := context.WithCancel(context.Background())
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
	time.AfterFunc(50*time.Millisecond, cancel)
	if _, err := client.Do(req); err == nil {
		t.Fatal("expected the cancellation")
	}
	if limit, _ := hosts.CurrentLimit(host); limit != 20 {
		t.Errorf("limit after a cancelled request = %d, want 20 (not distress)", limit)
	}

	timeoutClient := &http.Client{Transport: g.FeedbackRoundTripper(nil, LaneNormal, nil), Timeout: 50 * time.Millisecond}
	if _, err := timeoutClient.Get(srv.URL); err == nil {
		t.Fatal("expected the client timeout")
	}
	if limit, _ := hosts.CurrentLimit(host); limit >= 20 {
		t.Errorf("limit after a client timeout = %d, want backed off (distress)", limit)
	}
}
