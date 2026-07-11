package postmessage_handler_detect

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

func TestNew(t *testing.T) {
	t.Parallel()
	m := New()
	require.NotNil(t, m)
	assert.Equal(t, ModuleID, m.ID())
	assert.Equal(t, ModuleName, m.Name())
	assert.Equal(t, severity.Info, m.Severity())
}

// makeHTTPCtx builds a request/response pair with the given path, content type, and body.
func makeHTTPCtx(path, contentType, body string) *httpmsg.HttpRequestResponse {
	rawReq := []byte(fmt.Sprintf("GET %s HTTP/1.1\r\nHost: example.com\r\n\r\n", path))
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("example.com", 443, true),
		rawReq,
	)
	rawResp := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: %s\r\n\r\n%s", contentType, body)
	resp := httpmsg.NewHttpResponse([]byte(rawResp))
	return httpmsg.NewHttpRequestResponse(req, resp)
}

// scan is a helper that runs the module against a JS body and returns findings.
func scan(t *testing.T, path, body string) []*severityFinding {
	t.Helper()
	m := New()
	ctx := makeHTTPCtx(path, "application/javascript", body)
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	out := make([]*severityFinding, 0, len(results))
	for _, r := range results {
		assert.Equal(t, ModuleID, r.ModuleID)
		out = append(out, &severityFinding{name: r.Info.Name, sev: r.Info.Severity, kind: r.RecordKind})
	}
	return out
}

type severityFinding struct {
	name string
	sev  severity.Severity
	kind output.RecordKind
}

func find(findings []*severityFinding, name string) *severityFinding {
	for _, f := range findings {
		if f.name == name {
			return f
		}
	}
	return nil
}

// TestWildcardSend_Medium verifies a postMessage(..., "*") send is flagged Medium.
func TestWildcardSend_Medium(t *testing.T) {
	t.Parallel()
	body := `targetWindow.postMessage("hello other document!", "*");`
	f := find(scan(t, "/app/main.js", body), "postMessage Sent to Wildcard Origin (*)")
	require.NotNil(t, f, "expected wildcard-send finding")
	assert.Equal(t, severity.Medium, f.sev)
	assert.Equal(t, output.RecordKindCandidate, f.kind)
}

// TestWildcardSend_ObjectArg covers an object message argument plus a transfer list.
func TestWildcardSend_ObjectArg(t *testing.T) {
	t.Parallel()
	body := `iframe.contentWindow.postMessage({type:"ping",id:1}, "*", [port]);`
	f := find(scan(t, "/app/iframe.js", body), "postMessage Sent to Wildcard Origin (*)")
	require.NotNil(t, f, "expected wildcard-send finding with object arg + transfer list")
	assert.Equal(t, severity.Medium, f.sev)
}

// TestWildcardSend_ExplicitOrigin_NoFinding verifies an exact target origin is not flagged.
func TestWildcardSend_ExplicitOrigin_NoFinding(t *testing.T) {
	t.Parallel()
	body := `win.postMessage(data, "https://trusted.example.com");`
	f := find(scan(t, "/app/send.js", body), "postMessage Sent to Wildcard Origin (*)")
	assert.Nil(t, f, "exact target origin must not be flagged")
}

// TestWildcardSend_StarInsideObject_NoFinding ensures "*" inside an object literal does not match.
func TestWildcardSend_StarInsideObject_NoFinding(t *testing.T) {
	t.Parallel()
	body := `win.postMessage({selector:"*"});`
	f := find(scan(t, "/app/obj.js", body), "postMessage Sent to Wildcard Origin (*)")
	assert.Nil(t, f, `"*" inside the message object must not be flagged as a wildcard origin`)
}

// TestInlineHandler_NoOriginCheck_Medium flags an inline listener with no origin validation.
func TestInlineHandler_NoOriginCheck_Medium(t *testing.T) {
	t.Parallel()
	body := `window.addEventListener("message", function(e){ document.body.innerHTML = e.data; });`
	findings := scan(t, "/app/listen.js", body)
	f := find(findings, "postMessage Handler Without Origin Validation")
	require.NotNil(t, f, "expected unchecked-handler finding")
	assert.Equal(t, severity.Medium, f.sev)
	assert.Equal(t, output.RecordKindCandidate, f.kind)
	assert.Nil(t, find(findings, "postMessage Handler Detected"), "should not also be reported as Info")
}

// TestInlineHandler_ArrowNoOrigin_Medium covers the arrow-function form.
func TestInlineHandler_ArrowNoOrigin_Medium(t *testing.T) {
	t.Parallel()
	body := `addEventListener('message', e => handle(e.data));`
	f := find(scan(t, "/app/arrow.js", body), "postMessage Handler Without Origin Validation")
	require.NotNil(t, f, "expected unchecked-handler finding for global arrow listener")
	assert.Equal(t, severity.Medium, f.sev)
}

// TestInlineHandler_WithOriginGuard_Info keeps a handler that validates origin at Info.
func TestInlineHandler_WithOriginGuard_Info(t *testing.T) {
	t.Parallel()
	body := `window.addEventListener("message", function(e){ if (e.origin !== "https://trusted") return; use(e.data); });`
	findings := scan(t, "/app/guarded.js", body)
	f := find(findings, "postMessage Handler Detected")
	require.NotNil(t, f, "expected Info handler-detected finding")
	assert.Equal(t, severity.Info, f.sev)
	assert.Equal(t, output.RecordKindObservation, f.kind)
	assert.Nil(t, find(findings, "postMessage Handler Without Origin Validation"), "validated handler must not be Medium")
}

// TestNamedRefHandler_Info keeps a named-function reference handler at Info (body not visible).
func TestNamedRefHandler_Info(t *testing.T) {
	t.Parallel()
	body := `window.addEventListener("message", handleMessage);`
	findings := scan(t, "/app/named.js", body)
	f := find(findings, "postMessage Handler Detected")
	require.NotNil(t, f, "named-ref handler should be Info")
	assert.Equal(t, severity.Info, f.sev)
	assert.Nil(t, find(findings, "postMessage Handler Without Origin Validation"), "named ref must not be Medium")
}

// TestOnMessageAssignment covers window.onmessage = handler.
func TestOnMessageAssignment_Medium(t *testing.T) {
	t.Parallel()
	body := `window.onmessage = function(e){ render(e.data); };`
	f := find(scan(t, "/app/onmsg.js", body), "postMessage Handler Without Origin Validation")
	require.NotNil(t, f, "expected unchecked window.onmessage finding")
	assert.Equal(t, severity.Medium, f.sev)
}

// TestWebSocketOnMessage_NoFinding ensures WebSocket/EventSource handlers are not flagged.
func TestWebSocketOnMessage_NoFinding(t *testing.T) {
	t.Parallel()
	body := `ws.onmessage = function(e){ render(e.data); }; es.onmessage = (m) => log(m.data);`
	findings := scan(t, "/app/ws.js", body)
	assert.Empty(t, findings, "WebSocket/EventSource .onmessage must not be flagged")
}

// TestWorkerAddEventListener_NoFinding ensures Worker/ws message listeners are not flagged.
func TestWorkerAddEventListener_NoFinding(t *testing.T) {
	t.Parallel()
	body := `worker.addEventListener("message", e => process(e.data)); ws.addEventListener('message', onMsg);`
	findings := scan(t, "/app/worker.js", body)
	assert.Empty(t, findings, "worker/ws addEventListener('message') must not be flagged")
}

// TestWildcardSend_SchedulerEmptyPayload_NoFinding drops the MessageChannel
// feature-detection self-ping postMessage("","*"), a benign bundler pattern.
func TestWildcardSend_SchedulerEmptyPayload_NoFinding(t *testing.T) {
	t.Parallel()
	body := `!function(){return e.postMessage("","*"),e.onmessage=r}();`
	findings := scan(t, "/static/chunks/main-93dbaebda72da021.js", body)
	assert.Empty(t, findings, "empty-payload self-ping carries no data and must be dropped entirely")
}

// TestWildcardSend_SchedulerCoercion_NoFinding drops the scalar string-coercion
// scheduler token postMessage(id+"","*") emitted by setImmediate polyfills.
func TestWildcardSend_SchedulerCoercion_NoFinding(t *testing.T) {
	t.Parallel()
	body := `global.postMessage(id + '', '*'); c.postMessage(e+"","*");`
	findings := scan(t, "/vendors~main.js", body)
	assert.Empty(t, findings, "string-coercion scheduler tokens must be dropped")
}

// TestWildcardSend_SelfAlias_Low keeps an ambiguous same-window/alias send (e.g.
// axios' P.postMessage(e,"*")) as Low, out of the Medium bucket.
func TestWildcardSend_SelfAlias_Low(t *testing.T) {
	t.Parallel()
	body := `var P=window;P.postMessage(e,"*");`
	findings := scan(t, "/vendors~main-776354fc.js", body)
	assert.Nil(t, find(findings, "postMessage Sent to Wildcard Origin (*)"), "self-alias send must not be Medium")
	f := find(findings, "postMessage to Wildcard Origin (same-window)")
	require.NotNil(t, f, "self-alias send should still be reported at Low")
	assert.Equal(t, severity.Low, f.sev)
}

// TestWildcardSend_CrossDocument_Medium keeps a genuine cross-document data send
// (window.parent.postMessage({...},"*")) at Medium.
func TestWildcardSend_CrossDocument_Medium(t *testing.T) {
	t.Parallel()
	body := `window.parent.postMessage({Name:n,Payload:t},"*");`
	f := find(scan(t, "/Include/TEMP3/639173581050000000.js", body), "postMessage Sent to Wildcard Origin (*)")
	require.NotNil(t, f, "cross-document object send must be flagged")
	assert.Equal(t, severity.Medium, f.sev)
}

// TestServiceWorkerHandler_Info keeps a service-worker message handler at Info:
// SW message events are same-origin, so the missing origin check is not the
// cross-origin DOM-XSS class.
func TestServiceWorkerHandler_Info(t *testing.T) {
	t.Parallel()
	body := `self.addEventListener("message",e=>{const t=e.data;if(!t)return;handle(t);});`
	findings := scan(t, "/service-worker.js", body)
	assert.Nil(t, find(findings, "postMessage Handler Without Origin Validation"), "service-worker handler must not be Medium")
	f := find(findings, "postMessage Handler Detected")
	require.NotNil(t, f, "service-worker handler should still be reported at Info")
	assert.Equal(t, severity.Info, f.sev)
}

// TestCleanCode_NoFinding verifies benign JS produces no findings.
func TestCleanCode_NoFinding(t *testing.T) {
	t.Parallel()
	body := `function add(a, b) { return a + b; }`
	findings := scan(t, "/app/util.js", body)
	assert.Empty(t, findings)
}

// TestTestFileSuppressed verifies test/spec/mock files are skipped entirely.
func TestTestFileSuppressed(t *testing.T) {
	t.Parallel()
	body := `window.addEventListener("message", e => sink(e.data));`
	findings := scan(t, "/app/listen.test.js", body)
	assert.Empty(t, findings)
}
