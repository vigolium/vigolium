package registry_test

// Verification test for p8-062: under OLLAMA_EXPERIMENT=client2, the
// registry.Local dispatcher intercepts /api/pull and /api/delete BEFORE
// invoking its gin Fallback. The gin router carries allowedHostsMiddleware
// and CORS, so those paths run with zero middleware.
//
// Strategy: wrap the gin router with a middleware whose only job is to
// flip a counter when invoked. Issue requests to /api/pull, /api/delete,
// and /api/tags against a Local{Fallback: gin} and observe whether the
// middleware was reached.

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"

	"github.com/ollama/ollama/server/internal/registry"
)

func hostCheck(middlewareInvoked *bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		*middlewareInvoked = true
		host := c.Request.Host
		if host != "127.0.0.1:11434" && host != "localhost:11434" {
			c.AbortWithStatus(http.StatusForbidden)
			return
		}
		c.Next()
	}
}

func newSrv(t *testing.T) (*httptest.Server, *bool, *bool) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	middlewareInvoked := new(bool)
	fallbackInvoked := new(bool)

	r := gin.New()
	r.Use(cors.Default(), hostCheck(middlewareInvoked))

	r.POST("/api/pull", func(c *gin.Context) { *fallbackInvoked = true; c.Status(200) })
	r.DELETE("/api/delete", func(c *gin.Context) { *fallbackInvoked = true; c.Status(200) })
	r.GET("/api/tags", func(c *gin.Context) { *fallbackInvoked = true; c.Status(200) })

	local := &registry.Local{
		Logger:   slog.Default(),
		Fallback: r,
	}

	return httptest.NewServer(local), middlewareInvoked, fallbackInvoked
}

// Using GET on /api/pull — handlePull immediately returns errMethodNotAllowed
// (server.go:260-262) without touching s.Client. This lets us observe whether
// gin middleware was ever invoked.
func TestPullBypassesAllowedHosts(t *testing.T) {
	srv, middlewareInvoked, fallbackInvoked := newSrv(t)
	defer srv.Close()

	req, _ := http.NewRequest("GET", srv.URL+"/api/pull", nil)
	req.Host = "attacker.example.com"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	t.Logf("GET /api/pull (Host=attacker.example.com) -> status=%d body=%q", resp.StatusCode, body)
	t.Logf("host-check middleware invoked? %v   gin-fallback invoked? %v", *middlewareInvoked, *fallbackInvoked)

	if *middlewareInvoked {
		t.Errorf("allowedHostsMiddleware should NOT have been invoked on /api/pull under client2 dispatch.")
	} else {
		t.Logf("CONFIRMED: host-check middleware was NOT invoked — /api/pull bypass is real.")
	}
	if *fallbackInvoked {
		t.Errorf("gin /api/pull handler should NOT have been invoked under client2 dispatch.")
	}
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Logf("note: status %d (expected 405 from Local.handlePull)", resp.StatusCode)
	}
}

// Control: same hostile Host on /api/tags hits the gin fallback and SHOULD
// be blocked by hostCheck.
func TestTagsDoesNotBypass(t *testing.T) {
	srv, middlewareInvoked, _ := newSrv(t)
	defer srv.Close()

	req, _ := http.NewRequest("GET", srv.URL+"/api/tags", nil)
	req.Host = "attacker.example.com"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	t.Logf("GET /api/tags (Host=attacker.example.com) -> status=%d body=%q", resp.StatusCode, body)
	if !*middlewareInvoked {
		t.Errorf("host-check middleware SHOULD fire on /api/tags (fallback path).")
	} else {
		t.Logf("CONFIRMED: host-check middleware fired on fallback-dispatched /api/tags.")
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403 from host-check; got %d", resp.StatusCode)
	}
}

// Use GET on /api/delete — handleDelete returns errMethodNotAllowed for
// non-DELETE methods without touching Client. Observe middleware reach.
func TestDeleteBypassesAllowedHosts(t *testing.T) {
	srv, middlewareInvoked, fallbackInvoked := newSrv(t)
	defer srv.Close()

	req, _ := http.NewRequest("GET", srv.URL+"/api/delete", nil)
	req.Host = "attacker.example.com"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	t.Logf("GET /api/delete (Host=attacker.example.com) -> status=%d body=%q", resp.StatusCode, body)
	if *middlewareInvoked {
		t.Errorf("host-check middleware should NOT have been invoked on /api/delete under client2.")
	} else {
		t.Logf("CONFIRMED: host-check middleware was NOT invoked — /api/delete bypass is real.")
	}
	if *fallbackInvoked {
		t.Errorf("gin /api/delete handler should NOT have been invoked under client2 dispatch.")
	}
}
