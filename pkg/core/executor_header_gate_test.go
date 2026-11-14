package core

import (
	"context"
	"strings"
	"sync"
	"testing"

	protohttp "github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/work"
)

// vulnClassRecorder is a per-insertion-point module of a given vuln class that
// counts the header points it was handed, by lowercased name.
type vulnClassRecorder struct {
	activeStub
	class  string
	mu     sync.Mutex
	byName map[string]int
}

func (m *vulnClassRecorder) VulnClass() string { return m.class }

func (m *vulnClassRecorder) ScanPerInsertionPoint(_ *httpmsg.HttpRequestResponse, ip httpmsg.InsertionPoint, _ *protohttp.Requester, _ *modules.ScanContext) ([]*output.ResultEvent, error) {
	if ip.Type() == httpmsg.INS_HEADER {
		m.mu.Lock()
		m.byName[strings.ToLower(ip.Name())]++
		m.mu.Unlock()
	}
	return nil, nil
}

// Header points through the executor (ECON-1): noise headers produce no task
// at all; a logged header reaches SQLi once per origin and never XSS; an
// application header reaches both on every record.
func TestHeaderGateInExecutor(t *testing.T) {
	newRec := func(id, class string) *vulnClassRecorder {
		return &vulnClassRecorder{
			activeStub: activeStub{id: id, scopes: modules.ScanScopeInsertionPoint, canProc: true},
			class:      class,
			byName:     map[string]int{},
		}
	}
	sqli := newRec("sqli-rec", modkit.VulnClassSQLi)
	xss := newRec("xss-rec", modkit.VulnClassXSS)

	e := NewExecutor(ExecutorConfig{Workers: 1, SkipBaseline: true}, &sliceSource{},
		[]modules.ActiveModule{sqli, xss}, nil)
	for _, path := range []string{"/a", "/b"} {
		raw := "GET " + path + " HTTP/1.1\r\nHost: g.test\r\nUser-Agent: Mozilla/5.0\r\n" +
			"Sec-Fetch-Mode: navigate\r\nX-Tenant: acme\r\n\r\n"
		req := httpmsg.NewHttpRequestWithService(httpmsg.NewServiceSecure("g.test", 443, true), []byte(raw))
		rr := httpmsg.NewHttpRequestResponse(req, httpmsg.NewHttpResponse([]byte("HTTP/1.1 200 OK\r\n\r\nok")))
		e.processItem(context.Background(), work.NewWithModules(rr, nil))
	}

	if n := sqli.byName["sec-fetch-mode"] + xss.byName["sec-fetch-mode"]; n != 0 {
		t.Errorf("noise header dispatched %d times", n)
	}
	if n := sqli.byName["user-agent"]; n != 1 {
		t.Errorf("SQLi got User-Agent %d times over two records on one origin, want 1", n)
	}
	if n := xss.byName["user-agent"]; n != 0 {
		t.Errorf("XSS got User-Agent %d times, want 0", n)
	}
	if sqli.byName["x-tenant"] != 2 || xss.byName["x-tenant"] != 2 {
		t.Errorf("application header not tested per record: sqli=%d xss=%d", sqli.byName["x-tenant"], xss.byName["x-tenant"])
	}
	if e.ModuleSkips()["xss-rec"][SkipReasonHeaderGated] == 0 {
		t.Error("header_gated skips not counted")
	}

	// header_points: all — every header, every module, per record.
	all := newRec("xss-all", modkit.VulnClassXSS)
	e2 := NewExecutor(ExecutorConfig{Workers: 1, SkipBaseline: true, HeaderPointsAll: true}, &sliceSource{},
		[]modules.ActiveModule{all}, nil)
	raw := "GET /a HTTP/1.1\r\nHost: g.test\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
	req := httpmsg.NewHttpRequestWithService(httpmsg.NewServiceSecure("g.test", 443, true), []byte(raw))
	e2.processItem(context.Background(), work.NewWithModules(httpmsg.NewHttpRequestResponse(req, httpmsg.NewHttpResponse([]byte("HTTP/1.1 200 OK\r\n\r\nok"))), nil))
	if all.byName["user-agent"] != 1 {
		t.Errorf("header_points all: XSS got User-Agent %d times, want 1", all.byName["user-agent"])
	}
}
