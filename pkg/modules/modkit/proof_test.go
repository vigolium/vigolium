package modkit_test

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/output"
)

func reflectMarker(m string) string { return "<b>" + m + "</b>" }
func benignMarker(m string) string  { return m }

var bodyContainsBold = output.ProofOracle{Kind: output.ProofBodyContains, Value: "<b>" + output.MarkerPlaceholder + "</b>"}

func withHeaders(t *testing.T, rawURL, extra string) *httpmsg.HttpRequestResponse {
	t.Helper()
	rr := modtest.Request(t, rawURL)
	raw := strings.Replace(string(rr.Request().Raw()), "\r\n\r\n", "\r\n"+extra+"\r\n\r\n", 1)
	return httpmsg.NewHttpRequestResponse(httpmsg.NewHttpRequestWithService(rr.Service(), []byte(raw)), nil)
}

func TestBuildProofRecipeURLParam(t *testing.T) {
	rr := withHeaders(t, "http://127.0.0.1:8080/search?q=shoes&page=2",
		"Cookie: sid=secret\r\nAuthorization: Bearer tok\r\nX-Trace: 1")
	ip := modtest.InsertionPoint(t, rr, "q")

	r := modkit.BuildProofRecipe(rr, ip, reflectMarker, benignMarker, bodyContainsBold)
	if r == nil {
		t.Fatal("no recipe for a plain URL parameter")
	}
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	if r.Request.Method != "GET" || !r.Preconditions.MethodSafe {
		t.Errorf("method %q safe=%v", r.Request.Method, r.Preconditions.MethodSafe)
	}
	if !strings.HasPrefix(r.Request.URL, "http://127.0.0.1:8080/search?") || !strings.Contains(r.Request.URL, output.MarkerPlaceholder) {
		t.Errorf("attack url %q must be absolute and carry the placeholder", r.Request.URL)
	}
	if !strings.Contains(r.Request.URL, "page=2") {
		t.Errorf("attack url %q dropped the other parameter", r.Request.URL)
	}
	if r.Request.PayloadTemplate != "<b>"+output.MarkerPlaceholder+"</b>" {
		t.Errorf("payload_template = %q", r.Request.PayloadTemplate)
	}
	if r.Request.InsertionPoint != (output.ProofInsertionPoint{Type: "URL_PARAM", Name: "q"}) {
		t.Errorf("insertion_point = %+v", r.Request.InsertionPoint)
	}
	if r.Control.PayloadTemplate != output.MarkerPlaceholder || !strings.Contains(r.Control.URL, "q="+output.MarkerPlaceholder) {
		t.Errorf("control = %+v", r.Control)
	}
	for name := range r.Request.Headers {
		switch strings.ToLower(name) {
		case "cookie", "authorization", "host", "content-length":
			t.Errorf("recipe carries %s", name)
		}
	}
	if r.Request.Headers["X-Trace"] != "1" {
		t.Errorf("ordinary header lost: %v", r.Request.Headers)
	}
	if strings.Contains(r.Request.URL+r.Control.URL, "vgpm") {
		t.Error("the sentinel leaked into the recipe")
	}
}

func TestBuildProofRecipeJSONBody(t *testing.T) {
	rr := modtest.RequestJSON(t, "https://api.example:8443/v1/items", `{"name":"a","n":1}`)
	ip := modtest.InsertionPoint(t, rr, "name")
	r := modkit.BuildProofRecipe(rr, ip, reflectMarker, benignMarker, bodyContainsBold)
	if r == nil {
		t.Fatal("no recipe for a JSON field")
	}
	if r.Request.URL != "https://api.example:8443/v1/items" || r.Preconditions.MethodSafe {
		t.Errorf("url %q safe=%v", r.Request.URL, r.Preconditions.MethodSafe)
	}
	if !strings.Contains(r.Request.Body, output.MarkerPlaceholder) || r.Request.InsertionPoint.Type != "JSON_PARAM" {
		t.Errorf("body %q point %+v", r.Request.Body, r.Request.InsertionPoint)
	}
}

func TestBuildProofRecipeRefusals(t *testing.T) {
	t.Run("cookie point", func(t *testing.T) {
		rr := withHeaders(t, "http://127.0.0.1/x", "Cookie: sid=abc")
		ip := modtest.InsertionPointByType(t, rr, httpmsg.INS_PARAM_COOKIE)
		if r := modkit.BuildProofRecipe(rr, ip, reflectMarker, benignMarker, bodyContainsBold); r != nil {
			t.Fatalf("a cookie point must not yield a recipe: %+v", r)
		}
	})
	t.Run("encoding rewrites the marker", func(t *testing.T) {
		rr := modtest.Request(t, "http://127.0.0.1/search?q=shoes")
		ip := modtest.InsertionPoint(t, rr, "q")
		b64 := func(m string) string { return base64.StdEncoding.EncodeToString([]byte(reflectMarker(m))) }
		if r := modkit.BuildProofRecipe(rr, ip, b64, benignMarker, bodyContainsBold); r != nil {
			t.Fatalf("a payload whose marker does not survive must not yield a recipe: %+v", r)
		}
	})
	t.Run("invalid oracle", func(t *testing.T) {
		rr := modtest.Request(t, "http://127.0.0.1/search?q=shoes")
		ip := modtest.InsertionPoint(t, rr, "q")
		if r := modkit.BuildProofRecipe(rr, ip, reflectMarker, benignMarker, output.ProofOracle{Kind: output.ProofBodyContains}); r != nil {
			t.Fatalf("an oracle without a value must not yield a recipe: %+v", r)
		}
	})
}

func TestBuildProofRecipeReplays(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<p>" + r.URL.Query().Get("q") + "</p>"))
	}))
	defer srv.Close()
	rr := modtest.Request(t, srv.URL+"/search?q=shoes")
	ip := modtest.InsertionPoint(t, rr, "q")
	r := modkit.BuildProofRecipe(rr, ip, reflectMarker, benignMarker, bodyContainsBold)
	if got := modtest.ReplayProof(t, r); !got.Holds {
		t.Fatalf("recipe does not reproduce: attack %q control %q", got.AttackBody, got.ControlBody)
	}

	escaping := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := strings.NewReplacer("<", "&lt;", ">", "&gt;").Replace(r.URL.Query().Get("q"))
		_, _ = w.Write([]byte("<p>" + v + "</p>"))
	}))
	defer escaping.Close()
	rr = modtest.Request(t, escaping.URL+"/search?q=shoes")
	ip = modtest.InsertionPoint(t, rr, "q")
	r = modkit.BuildProofRecipe(rr, ip, reflectMarker, benignMarker, bodyContainsBold)
	if got := modtest.ReplayProof(t, r); got.Holds {
		t.Fatalf("an escaping sink must refute the recipe: attack %q", got.AttackBody)
	}
}
