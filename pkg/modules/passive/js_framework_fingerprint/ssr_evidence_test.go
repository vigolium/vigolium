package js_framework_fingerprint

import (
	"testing"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
)

func nextPage(host, extraHeaders string) *httpmsg.HttpRequestResponse {
	req := httpmsg.NewHttpRequestWithService(httpmsg.NewServiceSecure(host, 443, true),
		[]byte("GET / HTTP/1.1\r\nHost: "+host+"\r\n\r\n"))
	resp := httpmsg.NewHttpResponse([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n" + extraHeaders +
		"\r\n<html><script id=\"__NEXT_DATA__\" type=\"application/json\">{\"buildId\":\"b1\"}</script></html>"))
	return httpmsg.NewHttpRequestResponse(req, resp)
}

// nodejs is a backend stack tag: marked only on evidence of server rendering,
// never for a static export that can sit on any backend.
func TestNodejsMarkedOnlyOnSSREvidence(t *testing.T) {
	m := New()

	static := &modkit.ScanContext{TechStack: modkit.NewTechRegistry()}
	if _, err := m.ScanPerRequest(nextPage("static.test", ""), static); err != nil {
		t.Fatal(err)
	}
	if !static.TechStack.Has("static.test", "nextjs") {
		t.Fatal("nextjs not detected")
	}
	if static.TechStack.Has("static.test", "nodejs") {
		t.Fatal("nodejs marked on a static Next.js page with no SSR evidence")
	}
	if static.TechStack.HostKnown("static.test") != true {
		t.Fatal("nextjs is a stack tag; the host should be known")
	}

	ssr := &modkit.ScanContext{TechStack: modkit.NewTechRegistry()}
	if _, err := m.ScanPerRequest(nextPage("ssr.test", "X-Powered-By: Next.js\r\n"), ssr); err != nil {
		t.Fatal(err)
	}
	if !ssr.TechStack.Has("ssr.test", "nodejs") {
		t.Fatal("nodejs not marked despite X-Powered-By: Next.js")
	}
}
