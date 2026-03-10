package session

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseInlineSession(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    *Session
		wantErr bool
	}{
		{
			name:  "cookie session",
			input: "admin:Cookie:session=abc123",
			want: &Session{
				Name:    "admin",
				Role:    RoleCompare,
				Headers: map[string]string{"Cookie": "session=abc123"},
			},
		},
		{
			name:  "authorization bearer",
			input: "user2:Authorization:Bearer eyJhbGciOi",
			want: &Session{
				Name:    "user2",
				Role:    RoleCompare,
				Headers: map[string]string{"Authorization": "Bearer eyJhbGciOi"},
			},
		},
		{
			name:  "value with colons",
			input: "api:X-API-Key:abc:def:ghi",
			want: &Session{
				Name:    "api",
				Role:    RoleCompare,
				Headers: map[string]string{"X-API-Key": "abc:def:ghi"},
			},
		},
		{
			name:    "missing value",
			input:   "admin:Cookie",
			wantErr: true,
		},
		{
			name:    "empty name",
			input:   ":Cookie:value",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseInlineSession(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want.Name, got.Name)
			assert.Equal(t, tt.want.Role, got.Role)
			assert.Equal(t, tt.want.Headers, got.Headers)
		})
	}
}

func TestSessionValidate(t *testing.T) {
	tests := []struct {
		name    string
		session Session
		wantErr bool
	}{
		{
			name: "valid static",
			session: Session{
				Name:    "admin",
				Role:    RolePrimary,
				Headers: map[string]string{"Cookie": "sid=abc"},
			},
		},
		{
			name: "valid login",
			session: Session{
				Name: "user",
				Role: RoleCompare,
				Login: &LoginFlow{
					URL:    "https://app.com/login",
					Method: "POST",
					Extract: []ExtractRule{
						{Source: ExtractCookie},
					},
				},
			},
		},
		{
			name:    "missing name",
			session: Session{Headers: map[string]string{"Cookie": "x"}},
			wantErr: true,
		},
		{
			name:    "invalid role",
			session: Session{Name: "x", Role: "invalid"},
			wantErr: true,
		},
		{
			name: "both headers and login",
			session: Session{
				Name:    "x",
				Headers: map[string]string{"Cookie": "x"},
				Login:   &LoginFlow{URL: "http://x", Method: "POST", Extract: []ExtractRule{{Source: ExtractCookie}}},
			},
			wantErr: true,
		},
		{
			name: "login missing url",
			session: Session{
				Name:  "x",
				Login: &LoginFlow{Method: "POST", Extract: []ExtractRule{{Source: ExtractCookie}}},
			},
			wantErr: true,
		},
		{
			name: "login missing extract",
			session: Session{
				Name:  "x",
				Login: &LoginFlow{URL: "http://x", Method: "POST"},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.session.Validate()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestNewManager(t *testing.T) {
	t.Run("auto-assigns primary", func(t *testing.T) {
		sessions := []*Session{
			{Name: "a", Headers: map[string]string{"Cookie": "x"}},
			{Name: "b", Headers: map[string]string{"Cookie": "y"}},
		}
		mgr, err := NewManager(sessions)
		require.NoError(t, err)
		assert.Equal(t, "a", mgr.Primary().Name)
		assert.Equal(t, RolePrimary, mgr.Primary().Role)
		assert.Len(t, mgr.CompareSessions(), 1)
		assert.Equal(t, "b", mgr.CompareSessions()[0].Name)
	})

	t.Run("respects explicit primary", func(t *testing.T) {
		sessions := []*Session{
			{Name: "a", Role: RoleCompare, Headers: map[string]string{"Cookie": "x"}},
			{Name: "b", Role: RolePrimary, Headers: map[string]string{"Cookie": "y"}},
		}
		mgr, err := NewManager(sessions)
		require.NoError(t, err)
		assert.Equal(t, "b", mgr.Primary().Name)
		assert.Len(t, mgr.CompareSessions(), 1)
		assert.Equal(t, "a", mgr.CompareSessions()[0].Name)
	})

	t.Run("empty sessions fails", func(t *testing.T) {
		_, err := NewManager(nil)
		assert.Error(t, err)
	})
}

func TestLoadFromConfig(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "auth.yaml")

	content := `sessions:
  - name: admin
    role: primary
    headers:
      Cookie: "session=abc"
  - name: user2
    role: compare
    headers:
      Cookie: "session=xyz"
`
	require.NoError(t, os.WriteFile(configPath, []byte(content), 0644))

	sessions, err := LoadFromConfig(configPath)
	require.NoError(t, err)
	assert.Len(t, sessions, 2)
	assert.Equal(t, "admin", sessions[0].Name)
	assert.Equal(t, RolePrimary, sessions[0].Role)
	assert.Equal(t, "session=abc", sessions[0].Headers["Cookie"])
	assert.Equal(t, "user2", sessions[1].Name)
}

func TestSessionHeaderSlice(t *testing.T) {
	s := &Session{
		Name: "test",
		Headers: map[string]string{
			"Cookie":        "sid=abc",
			"Authorization": "Bearer token",
		},
	}
	headers := s.HeaderSlice()
	assert.Len(t, headers, 2)
	// Order is non-deterministic for maps, check both are present
	found := map[string]bool{}
	for _, h := range headers {
		found[h] = true
	}
	assert.True(t, found["Cookie: sid=abc"])
	assert.True(t, found["Authorization: Bearer token"])
}

func TestLoadFromInlineFlags(t *testing.T) {
	flags := []string{
		"admin:Cookie:session=abc",
		"user2:Authorization:Bearer token123",
	}
	sessions, err := LoadFromInlineFlags(flags)
	require.NoError(t, err)
	assert.Len(t, sessions, 2)
	assert.Equal(t, "admin", sessions[0].Name)
	assert.Equal(t, "session=abc", sessions[0].Headers["Cookie"])
	assert.Equal(t, "Bearer token123", sessions[1].Headers["Authorization"])
}
