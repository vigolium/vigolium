package core

import (
	"context"
	"testing"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/work"
)

// storeItem is a work item as a stored-record source hands it out.
func storeItem(t *testing.T, raw, resp string, completed *int) *work.WorkItem {
	t.Helper()
	rr, err := httpmsg.ParseRawRequestWithURL(raw, "https://w.test/items/1")
	if err != nil {
		t.Fatal(err)
	}
	if resp != "" {
		rr = rr.WithResponse(httpmsg.NewHttpResponse([]byte(resp)))
	}
	item := work.NewWithCallback(rr, nil, func() { *completed++ })
	item.RecordUUID = "rec-1"
	return item
}

// A stored request-only stub with a state-changing method is refused before
// the send — its baseline fetch would perform the write — unless the run
// allows writes. Safe methods, stubs that already carry a response, and items
// that did not come from the store are never refused.
func TestExecutorRefusesWriteTemplates(t *testing.T) {
	var completed int
	del := storeItem(t, "DELETE /items/1 HTTP/1.1\r\nHost: w.test\r\n\r\n", "", &completed)

	var unanswered []string
	e := &Executor{cfg: ExecutorConfig{OnUnanswered: func(_ *work.WorkItem, reason string, _ error) {
		unanswered = append(unanswered, reason)
	}}}
	ch := make(chan *work.WorkItem, 1)
	if !e.sendItem(context.Background(), del, ch) {
		t.Fatal("sendItem reported a cancelled context")
	}
	if len(ch) != 0 {
		t.Fatal("a DELETE template reached the workers")
	}
	if e.WriteTemplatesSkipped() != 1 || completed != 1 {
		t.Errorf("skipped=%d completed=%d, want 1 and 1", e.WriteTemplatesSkipped(), completed)
	}
	if len(unanswered) != 1 || unanswered[0] != SkipWriteTemplate {
		t.Errorf("OnUnanswered reasons = %v, want [%s]", unanswered, SkipWriteTemplate)
	}

	allow := &Executor{cfg: ExecutorConfig{AllowWrites: true}}
	if allow.refusesWriteTemplate(del) {
		t.Error("--allow-writes still refused the template")
	}
	var n int
	for _, item := range []*work.WorkItem{
		storeItem(t, "GET /items/1 HTTP/1.1\r\nHost: w.test\r\n\r\n", "", &n),
		storeItem(t, "OPTIONS /items/1 HTTP/1.1\r\nHost: w.test\r\n\r\n", "", &n),
		storeItem(t, "DELETE /items/1 HTTP/1.1\r\nHost: w.test\r\n\r\n", "HTTP/1.1 204 No Content\r\n\r\n", &n),
	} {
		if e.refusesWriteTemplate(item) {
			t.Errorf("refused %s (response %v)", item.Request.Request().Method(), item.Request.Response() != nil)
		}
	}
	fresh := storeItem(t, "POST /items HTTP/1.1\r\nHost: w.test\r\n\r\n", "", &n)
	fresh.RecordUUID = ""
	if e.refusesWriteTemplate(fresh) {
		t.Error("an input that did not come from the store was refused")
	}
}
