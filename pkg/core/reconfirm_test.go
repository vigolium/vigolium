package core

import (
	"context"
	"testing"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// reconfirmTestModule is a minimal modules.Module that can optionally opt into
// the body-differential safety net, for exercising reconfirmBodyDifferential's
// keep/drop decision branches that do not require a live HTTP request.
type reconfirmTestModule struct {
	id    string
	optIn bool
}

func (m *reconfirmTestModule) ID() string                                     { return m.id }
func (m *reconfirmTestModule) Name() string                                   { return m.id }
func (m *reconfirmTestModule) Description() string                            { return "" }
func (m *reconfirmTestModule) ShortDescription() string                       { return "" }
func (m *reconfirmTestModule) ConfirmationCriteria() string                   { return "" }
func (m *reconfirmTestModule) Severity() severity.Severity                    { return severity.High }
func (m *reconfirmTestModule) Confidence() severity.Confidence                { return severity.Firm }
func (m *reconfirmTestModule) ScanScopes() modules.ScanScope                  { return modkit.ScanScopeRequest }
func (m *reconfirmTestModule) Tags() []string                                 { return nil }
func (m *reconfirmTestModule) CanProcess(_ *httpmsg.HttpRequestResponse) bool { return true }

// optInModule embeds the base and implements BodyDifferentialConfirmable.
type optInModule struct {
	reconfirmTestModule
}

func (m *optInModule) ConfirmsByBodyDifferential() bool { return m.optIn }

func makeReconfirmItem(payloadRaw string) *httpmsg.HttpRequestResponse {
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("example.com", 443, true),
		[]byte(payloadRaw),
	)
	resp := httpmsg.NewHttpResponse([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nbaseline body"))
	return httpmsg.NewHttpRequestResponse(req, resp)
}

func TestReconfirmBodyDifferentialKeepPaths(t *testing.T) {
	baseReq := "GET /search?q=1 HTTP/1.1\r\nHost: example.com\r\n\r\n"
	e := &Executor{} // no httpClient

	t.Run("module does not implement the interface", func(t *testing.T) {
		m := &reconfirmTestModule{id: "no-iface"}
		item := makeReconfirmItem(baseReq)
		res := &output.ResultEvent{Request: "GET /search?q=PAYLOAD HTTP/1.1\r\nHost: example.com\r\n\r\n"}
		if !e.reconfirmBodyDifferential(context.Background(), m, res, item) {
			t.Error("a module that does not implement the interface must be kept")
		}
		if e.SuppressedFindings() != 0 {
			t.Error("no suppression expected")
		}
	})

	t.Run("module opts out", func(t *testing.T) {
		m := &optInModule{reconfirmTestModule{id: "opt-out", optIn: false}}
		item := makeReconfirmItem(baseReq)
		res := &output.ResultEvent{Request: "GET /search?q=PAYLOAD HTTP/1.1\r\nHost: example.com\r\n\r\n"}
		if !e.reconfirmBodyDifferential(context.Background(), m, res, item) {
			t.Error("a module that opts out must be kept")
		}
	})

	t.Run("nil item fails open", func(t *testing.T) {
		m := &optInModule{reconfirmTestModule{id: "opt-in", optIn: true}}
		res := &output.ResultEvent{Request: baseReq}
		if !e.reconfirmBodyDifferential(context.Background(), m, res, nil) {
			t.Error("nil item must fail open (keep)")
		}
	})

	t.Run("empty result.Request fails open", func(t *testing.T) {
		m := &optInModule{reconfirmTestModule{id: "opt-in", optIn: true}}
		item := makeReconfirmItem(baseReq)
		res := &output.ResultEvent{Request: ""}
		if !e.reconfirmBodyDifferential(context.Background(), m, res, item) {
			t.Error("empty result.Request must fail open (keep)")
		}
	})

	t.Run("payload equals baseline is skipped", func(t *testing.T) {
		m := &optInModule{reconfirmTestModule{id: "opt-in", optIn: true}}
		item := makeReconfirmItem(baseReq)
		// result.Request identical to the item's request → nothing to differentiate.
		res := &output.ResultEvent{Request: string(item.Request().Raw())}
		if !e.reconfirmBodyDifferential(context.Background(), m, res, item) {
			t.Error("identical payload/baseline must be kept (nothing to verify)")
		}
		if e.SuppressedFindings() != 0 {
			t.Error("no suppression expected when nothing to differentiate")
		}
	})

	t.Run("nil httpClient fails open", func(t *testing.T) {
		m := &optInModule{reconfirmTestModule{id: "opt-in", optIn: true}}
		item := makeReconfirmItem(baseReq)
		res := &output.ResultEvent{Request: "GET /search?q=PAYLOAD HTTP/1.1\r\nHost: example.com\r\n\r\n"}
		if !e.reconfirmBodyDifferential(context.Background(), m, res, item) {
			t.Error("nil httpClient must fail open (keep) — never drop without verifying")
		}
		if e.SuppressedFindings() != 0 {
			t.Error("no suppression expected when re-confirmation could not run")
		}
	})
}
