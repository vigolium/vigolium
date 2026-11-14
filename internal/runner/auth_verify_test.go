package runner

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/authentication"
	"github.com/vigolium/vigolium/pkg/database"
)

// TestNoteLoginVerification: a login that ran but could not be
// verified is warned about and recorded (auth_unverified), and under
// reauth.on_failure: abort it stops the scan.
func TestNoteLoginVerification(t *testing.T) {
	r, infra := preflightRunner(t)
	r.scanLogger = database.NewScanLogger(nil, "")
	results := []authentication.LoginResult{
		{Session: "ok", OK: true, Verified: true},
		{Session: "soft", OK: true, Verified: false, Reason: authentication.LoginReasonUnverified, Message: "no expect block"},
	}
	sessions := []*authentication.Session{{Name: "ok"}, {Name: "soft"}}
	if err := r.noteLoginVerification(results, sessions, infra); err != nil {
		t.Fatalf("continue policy must not stop the scan: %v", err)
	}
	if len(infra.authUnverified) != 1 || infra.authUnverified[0] != "soft" {
		t.Fatalf("authUnverified = %v, want [soft]", infra.authUnverified)
	}

	sessions[1].Reauth = &authentication.SessionReauth{OnFailure: authentication.ReauthAbort}
	if err := r.noteLoginVerification(results, sessions, infra); err == nil || !strings.Contains(err.Error(), "abort") {
		t.Fatalf("on_failure abort must stop the scan, got %v", err)
	}
}

// TestCheckAuthDifferential: when the target answers the session exactly as it
// answers an anonymous request, the scan says it may be unauthenticated.
func TestCheckAuthDifferential(t *testing.T) {
	srv, _ := countingServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html><body>public landing page, same for everyone</body></html>"))
	})
	r, infra := preflightRunner(t)
	r.options.Targets = []string{srv.URL + "/"}
	primary := &authentication.Session{Name: "user", Headers: map[string]string{"Authorization": "Bearer t"}}
	r.checkAuthDifferential(context.Background(), infra.httpRequester, primary, infra)
	if len(infra.authUnverified) != 1 || infra.authUnverified[0] != "user" {
		t.Fatalf("authUnverified = %v, want [user] for an indistinguishable response", infra.authUnverified)
	}

	srv2, _ := countingServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("login required"))
			return
		}
		_, _ = w.Write([]byte("<html>welcome back, user — your account dashboard</html>"))
	})
	infra.authUnverified = nil
	r.options.Targets = []string{srv2.URL + "/"}
	r.checkAuthDifferential(context.Background(), infra.httpRequester, primary, infra)
	if len(infra.authUnverified) != 0 {
		t.Fatalf("an authenticated difference must not warn: %v", infra.authUnverified)
	}
}
