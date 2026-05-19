package server

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadUsersFile_NotExists(t *testing.T) {
	users, err := LoadUsersFile("/tmp/nonexistent-vigolium-users.json")
	if err != nil {
		t.Fatalf("expected nil error for missing file, got: %v", err)
	}
	if users != nil {
		t.Fatalf("expected nil users for missing file, got: %v", users)
	}
}

func TestLoadUsersFile_Valid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "users.json")
	data := `[
		{"name": "admin", "email": "admin@test.com", "access_code": "key1", "role": "admin"},
		{"name": "viewer", "email": "viewer@test.com", "access_code": "key2", "role": "viewer"},
		{"name": "operator", "email": "op@test.com", "access_code": "key3", "role": "operator"}
	]`
	if err := os.WriteFile(path, []byte(data), 0644); err != nil {
		t.Fatal(err)
	}

	users, err := LoadUsersFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(users) != 3 {
		t.Fatalf("expected 3 users, got %d", len(users))
	}
	if users[0].Name != "admin" || users[0].Role != "admin" {
		t.Errorf("unexpected first user: %+v", users[0])
	}
}

func TestLoadUsersFile_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "users.json")
	if err := os.WriteFile(path, []byte(`{not json`), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadUsersFile(path)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestLoadUsersFile_DuplicateAccessCode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "users.json")
	data := `[
		{"name": "a", "email": "a@test.com", "access_code": "same", "role": "admin"},
		{"name": "b", "email": "b@test.com", "access_code": "same", "role": "viewer"}
	]`
	if err := os.WriteFile(path, []byte(data), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadUsersFile(path)
	if err == nil {
		t.Fatal("expected error for duplicate access_code")
	}
}

func TestLoadUsersFile_InvalidRole(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "users.json")
	data := `[{"name": "bad", "email": "bad@test.com", "access_code": "key1", "role": "superuser"}]`
	if err := os.WriteFile(path, []byte(data), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadUsersFile(path)
	if err == nil {
		t.Fatal("expected error for invalid role")
	}
}

func TestLoadUsersFile_EmptyAccessCode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "users.json")
	data := `[{"name": "empty", "email": "e@test.com", "access_code": "", "role": "admin"}]`
	if err := os.WriteFile(path, []byte(data), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadUsersFile(path)
	if err == nil {
		t.Fatal("expected error for empty access_code")
	}
}

func TestUserStore_Lookup(t *testing.T) {
	store := NewUserStore([]FileUser{
		{Name: "admin", Email: "admin@test.com", AccessCode: "key1", Role: "admin"},
		{Name: "viewer", Email: "viewer@test.com", AccessCode: "key2", Role: "viewer"},
	})

	// Found
	user := store.Lookup("key1")
	if user == nil {
		t.Fatal("expected user for key1")
	}
	if user.Name != "admin" || user.Role != RoleAdmin {
		t.Errorf("unexpected user: %+v", user)
	}

	// Not found
	if store.Lookup("nonexistent") != nil {
		t.Error("expected nil for unknown key")
	}

	// Nil store
	var nilStore *UserStore
	if nilStore.Lookup("key1") != nil {
		t.Error("expected nil from nil store")
	}
}

func TestLoadUsersFile_EmptyArray(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "users.json")
	if err := os.WriteFile(path, []byte(`[]`), 0644); err != nil {
		t.Fatal(err)
	}

	users, err := LoadUsersFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if users != nil {
		t.Fatalf("expected nil for empty array, got: %v", users)
	}
}

func TestBootstrapUsersFile_CreatesWithAccessCode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "subdir", "users.json")

	template := `[{"name": "vigolium-admin", "email": "", "access_code": "", "role": "admin"}]`

	created, err := BootstrapUsersFile(path, []byte(template))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !created {
		t.Fatal("expected file to be created")
	}

	// Verify the file was written with a generated access_code
	users, err := LoadUsersFile(path)
	if err != nil {
		t.Fatalf("failed to load bootstrapped file: %v", err)
	}
	if len(users) != 1 {
		t.Fatalf("expected 1 user, got %d", len(users))
	}
	if users[0].AccessCode == "" {
		t.Error("expected auto-generated access_code, got empty")
	}
	if users[0].Name != "vigolium-admin" {
		t.Errorf("expected name 'vigolium-admin', got %q", users[0].Name)
	}
	if len(users[0].AccessCode) < 10 {
		t.Errorf("access_code seems too short: %q", users[0].AccessCode)
	}
}

func TestBootstrapUsersFile_SkipsExisting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "users.json")

	// Write an existing file
	existing := `[{"name": "custom", "email": "", "access_code": "my_key", "role": "admin"}]`
	if err := os.WriteFile(path, []byte(existing), 0644); err != nil {
		t.Fatal(err)
	}

	template := `[{"name": "vigolium-admin", "email": "", "access_code": "", "role": "admin"}]`
	created, err := BootstrapUsersFile(path, []byte(template))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if created {
		t.Fatal("expected no creation when file exists")
	}

	// Verify original file is untouched
	users, err := LoadUsersFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if users[0].Name != "custom" || users[0].AccessCode != "my_key" {
		t.Errorf("existing file was modified: %+v", users[0])
	}
}

func TestDeterministicUUID(t *testing.T) {
	// Same input → same output
	a := deterministicUUID("test@example.com", "test")
	b := deterministicUUID("test@example.com", "test")
	if a != b {
		t.Errorf("expected deterministic UUIDs to match: %s != %s", a, b)
	}

	// Different input → different output
	c := deterministicUUID("other@example.com", "other")
	if a == c {
		t.Error("expected different UUIDs for different inputs")
	}

	// Falls back to name when email is empty
	d := deterministicUUID("", "fallback-name")
	e := deterministicUUID("", "fallback-name")
	if d != e {
		t.Errorf("expected deterministic UUIDs for name fallback: %s != %s", d, e)
	}
}
