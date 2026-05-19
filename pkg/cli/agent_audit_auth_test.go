package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveSecretValue_Literal(t *testing.T) {
	got, err := resolveSecretValue("sk-ant-literal", "api-key")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "sk-ant-literal" {
		t.Fatalf("got %q, want literal", got)
	}
}

func TestResolveSecretValue_Empty(t *testing.T) {
	got, err := resolveSecretValue("   ", "api-key")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "" {
		t.Fatalf("got %q, want empty", got)
	}
}

func TestResolveSecretValue_EnvIndirection(t *testing.T) {
	t.Setenv("VIG_TEST_KEY", "sk-from-env")
	got, err := resolveSecretValue("$VIG_TEST_KEY", "api-key")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "sk-from-env" {
		t.Fatalf("got %q, want sk-from-env", got)
	}
}

func TestResolveSecretValue_EnvUnsetErrors(t *testing.T) {
	_ = os.Unsetenv("VIG_TEST_NEVER_SET")
	_, err := resolveSecretValue("$VIG_TEST_NEVER_SET", "api-key")
	if err == nil {
		t.Fatal("expected error for unset env var")
	}
	if !strings.Contains(err.Error(), "VIG_TEST_NEVER_SET") {
		t.Fatalf("error %q should name the missing var", err.Error())
	}
}

func TestResolveSecretValue_EnvBareDollarErrors(t *testing.T) {
	if _, err := resolveSecretValue("$", "api-key"); err == nil {
		t.Fatal("expected error for bare $")
	}
}

func TestResolveSecretValue_FileIndirection(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key.txt")
	// Trailing newline is the common case for files written by `echo`.
	if err := os.WriteFile(path, []byte("sk-from-file\n"), 0o600); err != nil {
		t.Fatalf("write key file: %v", err)
	}
	got, err := resolveSecretValue("@"+path, "api-key")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "sk-from-file" {
		t.Fatalf("got %q, want sk-from-file", got)
	}
}

func TestResolveSecretValue_FileMissingErrors(t *testing.T) {
	if _, err := resolveSecretValue("@/no/such/path/vigolium-test", "api-key"); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestResolveSecretValue_FileEmptyErrors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.txt")
	if err := os.WriteFile(path, []byte("\n  \n"), 0o600); err != nil {
		t.Fatalf("write empty file: %v", err)
	}
	if _, err := resolveSecretValue("@"+path, "api-key"); err == nil {
		t.Fatal("expected error for whitespace-only file")
	}
}

func TestResolveSecretValue_FileBareAtErrors(t *testing.T) {
	if _, err := resolveSecretValue("@", "api-key"); err == nil {
		t.Fatal("expected error for bare @")
	}
}
