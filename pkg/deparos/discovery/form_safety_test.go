package discovery

import (
	"net/url"
	"testing"

	"github.com/vigolium/vigolium/pkg/deparos/spider"
	"github.com/vigolium/vigolium/pkg/deparos/spider/formparser"
)

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// Under the default read-only replay safety a POST form is withheld
// and kept as a request stub; a GET search form is queued for submission.
func TestQueueFormSubmission_ReplaySafetyGate(t *testing.T) {
	srv, _ := pathLoggingServer(t)
	cfg := testConfig(srv.URL)
	engine, err := testEngineWithConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Stop()

	src := mustURL(t, srv.URL+"/page")
	del := &spider.FormRequest{SourceURL: src, URL: mustURL(t, srv.URL+"/del"), Method: "POST",
		ContentType: "application/x-www-form-urlencoded", Body: "id=1",
		Inputs: []*spider.FormInputValue{{Name: "id", Value: "1", Type: formparser.InputTypeHidden}}}
	search := &spider.FormRequest{SourceURL: src, URL: mustURL(t, srv.URL+"/search?q=x"), Method: "GET",
		Inputs: []*spider.FormInputValue{{Name: "q", Value: "x", Type: formparser.InputTypeText}}}

	engine.queueFormSubmission([]*spider.FormRequest{del, search}, src, 0)

	if n := engine.formStructureCounter.Size(); n != 1 {
		t.Errorf("forms admitted for submission = %d, want 1 (the GET search form)", n)
	}
	var sawDel, sawSearch bool
	for _, o := range engine.RequestTemplateOutcomes() {
		switch o.Template.Request.URL.Rendered {
		case srv.URL + "/del":
			sawDel = true
			if o.Outcome != TemplateWithheldPolicy || o.Reason != "method:POST" {
				t.Errorf("/del outcome = %s/%s, want withheld_policy/method:POST", o.Outcome, o.Reason)
			}
		case srv.URL + "/search?q=x":
			sawSearch = true
		}
	}
	if !sawDel {
		t.Error("withheld POST form must survive as a request stub")
	}
	if sawSearch {
		t.Error("the submitted GET form must not be a withheld stub")
	}
}

func TestReplaySafety_FormReasons(t *testing.T) {
	u := mustURL(t, "https://a.test/search")
	cases := []struct {
		name   string
		policy ReplaySafety
		method string
		form   *spider.FormRequest
		want   string
	}{
		{"get read-only", ReplaySafetyReadOnly, "GET", &spider.FormRequest{URL: u}, ""},
		{"post read-only", ReplaySafetyReadOnly, "POST", &spider.FormRequest{URL: u}, "method:POST"},
		{"post state-changing", ReplaySafetyStateChanging, "POST", &spider.FormRequest{URL: u}, ""},
		{"metadata-only", ReplaySafetyMetadataOnly, "GET", &spider.FormRequest{URL: u}, "metadata-only"},
		{"password", ReplaySafetyStateChanging, "POST", &spider.FormRequest{URL: u, Inputs: []*spider.FormInputValue{{Name: "p", Type: formparser.InputTypePassword}}}, "form:password"},
		{"_method delete", ReplaySafetyStateChanging, "POST", &spider.FormRequest{URL: u, Inputs: []*spider.FormInputValue{{Name: "_method", Value: "delete"}}}, "form:method-override"},
		{"destructive action", ReplaySafetyStateChanging, "GET", &spider.FormRequest{URL: mustURL(t, "https://a.test/account/delete")}, "form:destructive"},
		{"destructive submit", ReplaySafetyStateChanging, "POST", &spider.FormRequest{URL: u, Inputs: []*spider.FormInputValue{{Name: "go", Value: "Sign out", Type: formparser.InputTypeSubmit}}}, "form:destructive"},
	}
	for _, c := range cases {
		if got := c.policy.FormWithheldReason(c.method, c.form); got != c.want {
			t.Errorf("%s: reason = %q, want %q", c.name, got, c.want)
		}
	}
}
