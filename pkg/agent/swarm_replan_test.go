package agent

import (
	"testing"

	"github.com/vigolium/vigolium/pkg/agent/recon"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

func TestReplanWorthwhile_StackDetectionsTrigger(t *testing.T) {
	report := &recon.TechStackReport{
		Stacks: []recon.StackDetection{{Name: "spring-boot", Tag: "spring"}},
	}
	if !replanWorthwhile(report, nil) {
		t.Error("stack detection should make replan worthwhile")
	}
}

func TestReplanWorthwhile_APISpecsTrigger(t *testing.T) {
	report := &recon.TechStackReport{
		APISpecs: []recon.APISpecDetection{{Kind: "graphql", URL: "/graphql"}},
	}
	if !replanWorthwhile(report, nil) {
		t.Error("API spec detection should make replan worthwhile")
	}
}

func TestReplanWorthwhile_LoginCandidatesTrigger(t *testing.T) {
	report := &recon.TechStackReport{
		LoginCandidates: []recon.LoginCandidate{{URL: "/login"}},
	}
	if !replanWorthwhile(report, nil) {
		t.Error("login candidate should make replan worthwhile")
	}
}

func TestReplanWorthwhile_MethodMatrixTriggers(t *testing.T) {
	report := &recon.TechStackReport{
		MethodMatrix: map[string][]string{"/api/x": {"PUT"}},
	}
	if !replanWorthwhile(report, nil) {
		t.Error("method matrix entry should make replan worthwhile")
	}
}

func TestReplanWorthwhile_JSSignalsTrigger(t *testing.T) {
	report := &recon.TechStackReport{
		JSSignals: []recon.JSFrameworkSignal{{Name: "next", Tag: "nextjs"}},
	}
	if !replanWorthwhile(report, nil) {
		t.Error("JS signal should make replan worthwhile")
	}
}

func TestReplanWorthwhile_AuthHeadersInRecordsTrigger(t *testing.T) {
	records := []*httpmsg.HttpRequestResponse{
		func() *httpmsg.HttpRequestResponse {
			raw := []byte("GET /api/me HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer abc\r\n\r\n")
			req := httpmsg.NewHttpRequest(raw)
			return httpmsg.NewHttpRequestResponse(req, nil)
		}(),
	}
	if !replanWorthwhile(nil, records) {
		t.Error("authenticated records should make replan worthwhile even without recon report")
	}
}

func TestReplanWorthwhile_NoSignalSkips(t *testing.T) {
	report := &recon.TechStackReport{} // empty
	records := []*httpmsg.HttpRequestResponse{
		func() *httpmsg.HttpRequestResponse {
			raw := []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n") // no auth
			req := httpmsg.NewHttpRequest(raw)
			return httpmsg.NewHttpRequestResponse(req, nil)
		}(),
	}
	if replanWorthwhile(report, records) {
		t.Error("empty recon + unauthenticated record should NOT trigger replan")
	}
}
