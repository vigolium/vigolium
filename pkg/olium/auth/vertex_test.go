package auth

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveVertexAuthPath_Explicit(t *testing.T) {
	got, err := resolveVertexAuthPath("/abs/sa.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "/abs/sa.json" {
		t.Errorf("expected /abs/sa.json, got %q", got)
	}
}

func TestResolveVertexAuthPath_FromEnv(t *testing.T) {
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "/from/env/sa.json")
	got, err := resolveVertexAuthPath("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "/from/env/sa.json" {
		t.Errorf("expected /from/env/sa.json, got %q", got)
	}
}

func TestResolveVertexAuthPath_HomeExpansion(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("home dir: %v", err)
	}
	got, err := resolveVertexAuthPath("~/Desktop/sa.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := filepath.Join(home, "Desktop", "sa.json")
	if got != want {
		t.Errorf("expected %q, got %q", want, got)
	}
}

func TestResolveVertexAuthPath_Missing(t *testing.T) {
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "")
	_, err := resolveVertexAuthPath("")
	if err == nil {
		t.Fatal("expected error when no path or env var is set")
	}
	if !strings.Contains(err.Error(), "no credential path") {
		t.Errorf("expected helpful 'no credential path' error, got %v", err)
	}
}
