package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/google/uuid"
	"github.com/vigolium/vigolium/internal/config"
)

// Role constants for user access control.
const (
	RoleAdmin    = "admin"
	RoleOperator = "operator"
	RoleViewer   = "viewer"
)

var validRoles = map[string]bool{
	RoleAdmin:    true,
	RoleOperator: true,
	RoleViewer:   true,
}

// vigoliumUserNamespace is a fixed UUID namespace for generating deterministic user UUIDs.
var vigoliumUserNamespace = uuid.MustParse("a1b2c3d4-e5f6-7890-abcd-ef1234567890")

// FileUser represents a single entry in the users JSON file.
type FileUser struct {
	Name       string `json:"name"`
	Email      string `json:"email"`
	AccessCode string `json:"access_code"`
	Role       string `json:"role"`
}

// ResolvedUser is the identity attached to a request after auth resolution.
type ResolvedUser struct {
	UUID  string
	Name  string
	Email string
	Role  string
}

// UserStore maps access codes to resolved users for O(1) lookup.
type UserStore struct {
	byAccessCode map[string]*ResolvedUser
}

// LoadUsersFile reads and parses a users JSON file from the given path.
// Returns nil, nil if the file does not exist or is empty (graceful fallback to legacy auth).
func LoadUsersFile(path string) ([]FileUser, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read users file: %w", err)
	}

	var users []FileUser
	if err := json.Unmarshal(data, &users); err != nil {
		return nil, fmt.Errorf("failed to parse users file: %w", err)
	}

	// Treat empty array as absent
	if len(users) == 0 {
		return nil, nil
	}

	// Validate entries
	seen := make(map[string]bool, len(users))
	for i, u := range users {
		if u.AccessCode == "" {
			return nil, fmt.Errorf("user at index %d (%q) has empty access_code", i, u.Name)
		}
		if !validRoles[u.Role] {
			return nil, fmt.Errorf("user %q has invalid role %q (valid: admin, operator, viewer)", u.Name, u.Role)
		}
		if seen[u.AccessCode] {
			return nil, fmt.Errorf("duplicate access_code for user %q", u.Name)
		}
		seen[u.AccessCode] = true
	}

	return users, nil
}

// NewUserStore builds a store from a slice of FileUser entries.
// Each user gets a deterministic UUID v5 derived from their email (or name if no email).
func NewUserStore(entries []FileUser) *UserStore {
	s := &UserStore{
		byAccessCode: make(map[string]*ResolvedUser, len(entries)),
	}
	for _, e := range entries {
		s.byAccessCode[e.AccessCode] = &ResolvedUser{
			UUID:  deterministicUUID(e.Email, e.Name),
			Name:  e.Name,
			Email: e.Email,
			Role:  e.Role,
		}
	}
	return s
}

// Lookup returns the resolved user for an access code, or nil if not found.
func (s *UserStore) Lookup(accessCode string) *ResolvedUser {
	if s == nil {
		return nil
	}
	return s.byAccessCode[accessCode]
}

// LookupByNameAndCode returns the resolved user matching both name and access code, or nil.
func (s *UserStore) LookupByNameAndCode(name, accessCode string) *ResolvedUser {
	if s == nil {
		return nil
	}
	user := s.byAccessCode[accessCode]
	if user != nil && user.Name == name {
		return user
	}
	return nil
}

// BootstrapUsersFile creates the users file from the embedded default template
// if it does not already exist. Each user with an empty access_code gets a
// freshly generated one. Returns true if a new file was created.
func BootstrapUsersFile(path string, defaultJSON []byte) (bool, error) {
	// Ensure parent directory exists
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return false, fmt.Errorf("failed to create users file directory: %w", err)
	}

	// Atomic create: O_EXCL fails if the file already exists (no TOCTOU race).
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return false, nil
		}
		return false, fmt.Errorf("failed to create users file: %w", err)
	}
	defer func() { _ = f.Close() }()

	var users []FileUser
	if err := json.Unmarshal(defaultJSON, &users); err != nil {
		return false, fmt.Errorf("failed to parse default users template: %w", err)
	}

	// Auto-generate access codes for entries that have none
	for i := range users {
		if users[i].AccessCode == "" {
			users[i].AccessCode = generateAccessCode()
		}
	}

	data, err := json.MarshalIndent(users, "", "  ")
	if err != nil {
		return false, fmt.Errorf("failed to marshal users: %w", err)
	}
	data = append(data, '\n')

	if _, err := f.Write(data); err != nil {
		return false, fmt.Errorf("failed to write users file: %w", err)
	}
	return true, nil
}

// generateAccessCode returns a random access code with a "vgl_" prefix.
func generateAccessCode() string {
	return "vgl_" + config.GenerateRandomHex(32)
}

// deterministicUUID generates a proper UUID v5 from the given identifiers
// using a fixed vigolium namespace.
func deterministicUUID(email, name string) string {
	key := email
	if key == "" {
		key = name
	}
	return uuid.NewSHA1(vigoliumUserNamespace, []byte(key)).String()
}
