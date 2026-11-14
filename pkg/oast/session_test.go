package oast

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/projectdiscovery/interactsh/pkg/server"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/oast/oastclass"
)

// TestKeepSession_LateCallbackCorrelates is MISS-37: an interactsh payload's
// context is persisted, the session is kept (not deregistered) when the scan
// closes, a callback arriving after the process's tracker is gone still
// correlates from oast_payloads, and a later poll resumes the stored session
// and can close it.
func TestKeepSession_LateCallbackCorrelates(t *testing.T) {
	var deregistered atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/deregister" {
			deregistered.Add(1)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"message":"registration successful"}`))
	}))
	t.Cleanup(srv.Close)

	repo := newOASTTestRepo(t)
	ctx := context.Background()
	svc, _ := New(&config.OASTConfig{Enabled: true, ServerURL: srv.URL, KeepSession: true}, nil, repo, "scan-1", database.DefaultProjectUUID, nil)
	if err := svc.WaitReady(ctx, 5*time.Second); err != nil {
		t.Fatalf("WaitReady: %v", err)
	}
	cb := svc.GenerateURLFor(oastclass.SSRF, "https://app.test/fetch?u=x", "u", "ssrf", "ssrf-oast", "")
	if cb == "" {
		t.Fatal("no callback URL minted")
	}
	svc.RecordPayload(cb, "http://"+cb+"/")
	svc.Close()

	if n := deregistered.Load(); n != 0 {
		t.Fatalf("/deregister = %d, want 0: the session must be kept for late callbacks", n)
	}
	sessions, err := repo.ListOpenOASTSessions(ctx, database.DefaultProjectUUID, "scan-1")
	if err != nil || len(sessions) != 1 || sessions[0].SecretKey == "" || sessions[0].PrivateKey == "" {
		t.Fatalf("kept sessions = %+v, err %v; want one with key material", sessions, err)
	}
	nonce := extractNonce(cb)
	stored, err := repo.GetOASTPayload(ctx, database.DefaultProjectUUID, nonce)
	if err != nil || stored == nil || stored.Payload != "http://"+cb+"/" || stored.Class != string(oastclass.SSRF) {
		t.Fatalf("persisted payload = %+v, err %v", stored, err)
	}

	// A fresh process (as a poll is): no tracker, only the store.
	late := &Service{repo: repo, scanUUID: "scan-1", projectUUID: database.DefaultProjectUUID}
	if !late.handleInteractionCorrelated(&server.Interaction{
		Protocol: "http", UniqueID: nonce, FullId: nonce,
		RawRequest:    "GET / HTTP/1.1\r\nHost: " + cb + "\r\nUser-Agent: Go-http-client/1.1\r\n\r\n",
		RemoteAddress: "203.0.113.9", Timestamp: time.Now(),
	}) {
		t.Fatal("late callback did not correlate from oast_payloads")
	}
	n, err := database.NewFindingsQueryBuilder(repo.DB(), database.QueryFilters{ProjectUUID: database.DefaultProjectUUID}).Count(ctx)
	if err != nil || n != 1 {
		t.Fatalf("findings = %d, err %v; want 1", n, err)
	}

	res := PollSessions(ctx, repo, sessions, PollOptions{Wait: 50 * time.Millisecond, Close: true})
	if len(res) != 1 || res[0].Error != "" || !res[0].Closed {
		t.Fatalf("poll result = %+v", res)
	}
	if deregistered.Load() != 1 {
		t.Errorf("/deregister after poll --close = %d, want 1", deregistered.Load())
	}
	open, _ := repo.ListOpenOASTSessions(ctx, database.DefaultProjectUUID, "")
	if len(open) != 0 {
		t.Errorf("open sessions after close = %d, want 0", len(open))
	}
}

// TestKeepSession_OffDeregisters: keep_session off (and every -S scan) keeps
// the old behaviour: deregister on Close, nothing stored.
func TestKeepSession_OffDeregisters(t *testing.T) {
	var deregistered atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/deregister" {
			deregistered.Add(1)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"message":"registration successful"}`))
	}))
	t.Cleanup(srv.Close)
	repo := newOASTTestRepo(t)
	svc, _ := New(&config.OASTConfig{Enabled: true, ServerURL: srv.URL}, nil, repo, "scan-2", database.DefaultProjectUUID, nil)
	if err := svc.WaitReady(context.Background(), 5*time.Second); err != nil {
		t.Fatalf("WaitReady: %v", err)
	}
	svc.Close()
	if deregistered.Load() != 1 {
		t.Errorf("/deregister = %d, want 1", deregistered.Load())
	}
	if s, _ := repo.ListOpenOASTSessions(context.Background(), "", ""); len(s) != 0 {
		t.Errorf("sessions stored = %d, want 0", len(s))
	}
}
