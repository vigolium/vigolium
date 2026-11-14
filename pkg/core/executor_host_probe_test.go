package core

import (
	"context"
	"fmt"
	"net"
	stdhttp "net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/work"
)

// hostProbeModule is a run-once-per-host probe written the way the real ones
// are: it claims the host through modkit.BeginHostProbe, sends its probe, and
// swallows a send error (returning a clean nil) like most modules do.
type hostProbeModule struct {
	activeStub
	ds     *dedup.DiskSet
	calls  atomic.Int32 // ScanPerHost invocations
	probes atomic.Int32 // probes actually sent (claim granted)
	sent   atomic.Int32 // probes that got an answer
}

func (m *hostProbeModule) ScanPerHost(item *httpmsg.HttpRequestResponse, client *http.Requester, scanCtx *modules.ScanContext) ([]*output.ResultEvent, error) {
	m.calls.Add(1)
	if !modkit.BeginHostProbe(scanCtx, client, m.ds, item.Service().Host()) {
		return nil, nil
	}
	m.probes.Add(1)
	if _, _, err := client.Execute(item, http.Options{}); err == nil {
		m.sent.Add(1)
	}
	return nil, nil
}

// A run-once host probe whose requests failed transiently — here the target
// resets every connection during the first record — must neither claim the
// host in its own dedup set nor keep the executor's per-host claim, so the
// next record of the host runs the probe again (MISS-19). Before, the module
// claimed the host before probing and returned nil after swallowing the send
// error: the executor saw a clean run, and the host was never probed again.
func TestPerHostProbeRetriedAfterTransientTransportFailure(t *testing.T) {
	var failing atomic.Bool
	failing.Store(true)
	srv := httptest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, _ *stdhttp.Request) {
		if failing.Load() {
			if hj, ok := w.(stdhttp.Hijacker); ok {
				if conn, _, err := hj.Hijack(); err == nil {
					_ = conn.Close() // connection reset / EOF: a transient transport error
					return
				}
			}
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	host, portStr, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(portStr)

	ds, err := dedup.NewDiskSet(dedup.DefaultDiskSetOptions)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ds.Close() }()

	mod := &hostProbeModule{
		activeStub: activeStub{id: "host-probe-retry", scopes: modules.ScanScopeHost, canProc: true},
		ds:         ds,
	}
	e := NewExecutor(ExecutorConfig{Workers: 1, SkipBaseline: true, HTTPRequester: newAbandonTestRequester(t)},
		&sliceSource{}, []modules.ActiveModule{mod}, nil)

	makeItem := func(i int) *work.WorkItem {
		svc, err := httpmsg.NewService(host, port, "http")
		if err != nil {
			t.Fatal(err)
		}
		raw := []byte(fmt.Sprintf("GET /p%d HTTP/1.1\r\nHost: %s\r\n\r\n", i, srv.Listener.Addr().String()))
		rr := httpmsg.NewHttpRequestResponse(httpmsg.NewHttpRequestWithService(svc, raw),
			httpmsg.NewHttpResponse([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nok")))
		return work.NewWithModules(rr, nil)
	}

	// Record 1: every probe request is reset.
	e.processItem(context.Background(), makeItem(1))
	if got := mod.probes.Load(); got != 1 || mod.sent.Load() != 0 {
		t.Fatalf("record 1: probes=%d sent=%d, want 1 probe that got no answer", got, mod.sent.Load())
	}
	if ds.Contains(host) {
		t.Fatal("a probe whose requests all failed transiently must not claim the host")
	}

	// Record 2: the target recovered — the probe must run again and land.
	failing.Store(false)
	e.processItem(context.Background(), makeItem(2))
	if got := mod.probes.Load(); got != 2 || mod.sent.Load() != 1 {
		t.Fatalf("record 2: probes=%d sent=%d, want the probe retried and answered", got, mod.sent.Load())
	}
	if !ds.Contains(host) {
		t.Fatal("a clean probe must claim the host")
	}

	// Record 3: claimed for good — neither the executor nor the module runs it.
	e.processItem(context.Background(), makeItem(3))
	if got := mod.probes.Load(); got != 2 {
		t.Fatalf("record 3: probes=%d, want no further probe once the host is claimed", got)
	}
	if got := mod.calls.Load(); got != 2 {
		t.Fatalf("calls=%d, want 2 (executor keeps the per-host claim after the clean run)", got)
	}
}
