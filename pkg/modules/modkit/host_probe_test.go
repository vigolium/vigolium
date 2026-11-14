package modkit

import (
	"testing"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

func newProbeSet(t *testing.T) *dedup.DiskSet {
	t.Helper()
	ds, err := dedup.NewDiskSet(dedup.DefaultDiskSetOptions)
	if err != nil {
		t.Fatalf("NewDiskSet: %v", err)
	}
	t.Cleanup(func() { _ = ds.Close() })
	return ds
}

// Outside the executor the claim is taken up front, exactly like IsSeen.
func TestBeginHostProbe_ImmediateWithoutDeferral(t *testing.T) {
	ds := newProbeSet(t)
	sc := &ScanContext{}
	c := &http.Requester{}
	if !BeginHostProbe(sc, c, ds, "h") {
		t.Fatal("first probe must run")
	}
	if BeginHostProbe(sc, c, ds, "h") {
		t.Fatal("second probe must be skipped: claim is immediate without DeferHostClaims")
	}
	if !BeginHostProbe(nil, nil, nil, "h") {
		t.Fatal("a nil set always probes")
	}
}

// Under the executor the claim commits only on a clean settle; a failed call
// leaves the host to be probed again, at most maxHostProbeAttempts times.
func TestBeginHostProbe_DeferredSettle(t *testing.T) {
	ds := newProbeSet(t)
	sc := &ScanContext{DeferHostClaims: true}

	call1, call2 := &http.Requester{}, &http.Requester{}
	if !BeginHostProbe(sc, call1, ds, "h") {
		t.Fatal("first probe must run")
	}
	// While call1 is probing, a concurrent call must not start a second probe.
	if BeginHostProbe(sc, call2, ds, "h") {
		t.Fatal("a key in flight must not be probed twice concurrently")
	}
	sc.SettleHostProbes(call2, true) // nothing pending on call2: no-op
	if ds.Contains("h") {
		t.Fatal("settling an unrelated call must not commit h")
	}

	sc.SettleHostProbes(call1, false) // transient failure: dropped
	if ds.Contains("h") {
		t.Fatal("a failed probe must not claim the host")
	}
	if !BeginHostProbe(sc, call2, ds, "h") {
		t.Fatal("after a failed probe the next call must probe again")
	}
	sc.SettleHostProbes(call2, true)
	if !ds.Contains("h") {
		t.Fatal("a clean probe must claim the host")
	}
	if BeginHostProbe(sc, call1, ds, "h") {
		t.Fatal("a claimed host must not be probed again")
	}

	// A host that keeps failing is claimed after maxHostProbeAttempts.
	for i := 0; i < maxHostProbeAttempts; i++ {
		c := &http.Requester{}
		if !BeginHostProbe(sc, c, ds, "dead") {
			t.Fatalf("attempt %d must probe", i+1)
		}
		sc.SettleHostProbes(c, false)
	}
	if !ds.Contains("dead") {
		t.Fatal("a host failing every attempt must be claimed once the attempts are spent")
	}
	if n := sc.hostProbesPending.Load(); n != 0 {
		t.Fatalf("pending = %d after every call settled, want 0", n)
	}
}

// BeginHostProbeFor resolves the module's lazy set against the scan's dedup
// manager and keys on the record's service host, so two records of one host
// (different paths and ports) share one claim.
func TestBeginHostProbeFor(t *testing.T) {
	mgr := dedup.NewManager()
	t.Cleanup(mgr.Close)
	sc := &ScanContext{DedupManager: mgr}
	lazy := dedup.LazyDiskSet("host_probe_for_test")
	c := &http.Requester{}
	item := func(port int, path string) *httpmsg.HttpRequestResponse {
		return httpmsg.NewRequestResponseRaw([]byte("GET "+path+" HTTP/1.1\r\nHost: h.test\r\n\r\n"),
			httpmsg.NewServiceSecure("h.test", port, port == 443))
	}
	if !BeginHostProbeFor(sc, c, &lazy, item(443, "/a")) {
		t.Fatal("first probe of the host must run")
	}
	if BeginHostProbeFor(sc, c, &lazy, item(8443, "/b")) {
		t.Fatal("a second record of the same host must not probe again")
	}
	if BeginHostProbeFor(sc, c, &lazy, &httpmsg.HttpRequestResponse{}) {
		t.Fatal("a record without a service has no host to probe")
	}
	if !BeginHostProbeFor(nil, c, &lazy, item(443, "/a")) {
		t.Fatal("without a scan context (no dedup manager) the probe always runs")
	}
}
