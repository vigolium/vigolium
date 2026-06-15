package core

import (
	"fmt"
	"testing"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
)

// contentClassStub satisfies modules.Module. When required is set it also
// reports as modules.ContentClassAware.
type contentClassStub struct {
	techStub
	required []string
}

func (m *contentClassStub) RequiredContentClasses() []string { return m.required }

// makeItemWithContentType builds an item whose response carries the given
// Content-Type (empty header omitted).
func makeItemWithContentType(host, contentType string) *httpmsg.HttpRequestResponse {
	rawReq := []byte(fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\n\r\n", host))
	req := httpmsg.NewHttpRequestWithService(httpmsg.NewServiceSecure(host, 443, true), rawReq)
	var rawResp []byte
	if contentType == "" {
		rawResp = []byte("HTTP/1.1 200 OK\r\n\r\n{}")
	} else {
		rawResp = []byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: %s\r\n\r\n{}", contentType))
	}
	resp := httpmsg.NewHttpResponse(rawResp)
	return httpmsg.NewHttpRequestResponse(req, resp)
}

func TestPassesContentClassFilter(t *testing.T) {
	newExec := func(disabled bool, hostSeed map[string]modkit.ContentClass) *Executor {
		e := &Executor{cfg: ExecutorConfig{TechFilterDisabled: disabled}}
		e.scanCtx = &modules.ScanContext{ContentClass: modkit.NewContentClassRegistry()}
		for h, c := range hostSeed {
			e.scanCtx.ContentClass.Set(h, c)
		}
		return e
	}

	htmlMod := func() modules.Module {
		return &contentClassStub{techStub: techStub{id: "clickjacking-detect"}, required: []string{"html"}}
	}
	agnosticMod := func() modules.Module {
		return &contentClassStub{techStub: techStub{id: "secret-detect"}}
	}

	t.Run("html module runs on html response", func(t *testing.T) {
		e := newExec(false, nil)
		if !e.passesContentClassFilter(htmlMod(), makeItemWithContentType("a.com", "text/html")) {
			t.Fatal("html module must run on html response")
		}
	})

	t.Run("html module skips json response", func(t *testing.T) {
		e := newExec(false, nil)
		if e.passesContentClassFilter(htmlMod(), makeItemWithContentType("a.com", "application/json")) {
			t.Fatal("html module must skip json response")
		}
	})

	t.Run("html module fails open on missing content-type", func(t *testing.T) {
		e := newExec(false, nil)
		if !e.passesContentClassFilter(htmlMod(), makeItemWithContentType("a.com", "")) {
			t.Fatal("html module must fail open when content-type and host class are unknown")
		}
	})

	t.Run("host fallback skips html module on json api host", func(t *testing.T) {
		e := newExec(false, map[string]modkit.ContentClass{"a.com": modkit.ContentClassJSON})
		// Record has no content-type of its own, but the host root was a JSON API.
		if e.passesContentClassFilter(htmlMod(), makeItemWithContentType("a.com", "")) {
			t.Fatal("html module must defer when record type unknown but host root is JSON")
		}
	})

	t.Run("record content-type wins over host fallback", func(t *testing.T) {
		e := newExec(false, map[string]modkit.ContentClass{"a.com": modkit.ContentClassJSON})
		// Host root was JSON, but THIS record is HTML — the record wins, module runs.
		if !e.passesContentClassFilter(htmlMod(), makeItemWithContentType("a.com", "text/html")) {
			t.Fatal("record's own html content-type must override the host json fallback")
		}
	})

	t.Run("content-agnostic module always runs", func(t *testing.T) {
		e := newExec(false, nil)
		if !e.passesContentClassFilter(agnosticMod(), makeItemWithContentType("a.com", "application/json")) {
			t.Fatal("agnostic module must run on any content type")
		}
	})

	t.Run("disabled filter always passes", func(t *testing.T) {
		e := newExec(true, nil)
		if !e.passesContentClassFilter(htmlMod(), makeItemWithContentType("a.com", "application/json")) {
			t.Fatal("disabled tech filter must also disable content-class gating")
		}
	})
}
