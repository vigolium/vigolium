package authentication

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

func TestLoadFromAuthFilesBundle(t *testing.T) {
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

	sessions, err := LoadFromAuthFiles([]string{configPath}, "")
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

func TestLoadFromAuthFilesBundleJSON(t *testing.T) {
	dir := t.TempDir()

	t.Run("json by extension", func(t *testing.T) {
		configPath := filepath.Join(dir, "auth.json")
		content := `{
  "sessions": [
    {
      "name": "admin",
      "role": "primary",
      "headers": {"Cookie": "session=abc"}
    },
    {
      "name": "user2",
      "role": "compare",
      "login": {
        "url": "https://app.com/api/login",
        "method": "POST",
        "content_type": "application/json",
        "body": "{\"email\":\"test@test.com\",\"password\":\"pass\"}",
        "extract": [
          {"source": "json", "path": "$.token", "apply_as": "Authorization: Bearer {value}"}
        ]
      }
    }
  ]
}`
		require.NoError(t, os.WriteFile(configPath, []byte(content), 0644))

		sessions, err := LoadFromAuthFiles([]string{configPath}, "")
		require.NoError(t, err)
		assert.Len(t, sessions, 2)
		assert.Equal(t, "admin", sessions[0].Name)
		assert.Equal(t, RolePrimary, sessions[0].Role)
		assert.Equal(t, "session=abc", sessions[0].Headers["Cookie"])
		assert.Equal(t, "user2", sessions[1].Name)
		require.NotNil(t, sessions[1].Login)
		assert.Equal(t, "https://app.com/api/login", sessions[1].Login.URL)
		assert.Equal(t, "POST", sessions[1].Login.Method)
		assert.Equal(t, "application/json", sessions[1].Login.ContentType)
		assert.Len(t, sessions[1].Login.Extract, 1)
		assert.Equal(t, ExtractJSON, sessions[1].Login.Extract[0].Source)
		assert.Equal(t, "$.token", sessions[1].Login.Extract[0].Path)
		assert.Equal(t, "Authorization: Bearer {value}", sessions[1].Login.Extract[0].ApplyAs)
	})

	t.Run("json by content sniffing", func(t *testing.T) {
		// No .json extension but content starts with {
		configPath := filepath.Join(dir, "auth-config")
		content := `{"sessions": [{"name": "api", "role": "primary", "headers": {"X-API-Key": "secret"}}]}`
		require.NoError(t, os.WriteFile(configPath, []byte(content), 0644))

		sessions, err := LoadFromAuthFiles([]string{configPath}, "")
		require.NoError(t, err)
		assert.Len(t, sessions, 1)
		assert.Equal(t, "api", sessions[0].Name)
		assert.Equal(t, "secret", sessions[0].Headers["X-API-Key"])
	})
}

func TestLoadFromAuthFilesSingleSession(t *testing.T) {
	dir := t.TempDir()

	t.Run("json single session", func(t *testing.T) {
		sessionPath := filepath.Join(dir, "session.json")
		content := `{"name": "admin", "role": "primary", "headers": {"Cookie": "sid=abc"}}`
		require.NoError(t, os.WriteFile(sessionPath, []byte(content), 0644))

		sessions, err := LoadFromAuthFiles([]string{sessionPath}, "")
		require.NoError(t, err)
		assert.Len(t, sessions, 1)
		assert.Equal(t, "admin", sessions[0].Name)
		assert.Equal(t, "sid=abc", sessions[0].Headers["Cookie"])
	})

	t.Run("yaml single session", func(t *testing.T) {
		sessionPath := filepath.Join(dir, "single.yaml")
		content := "name: admin\nrole: primary\nheaders:\n  Cookie: sid=abc\n"
		require.NoError(t, os.WriteFile(sessionPath, []byte(content), 0644))

		sessions, err := LoadFromAuthFiles([]string{sessionPath}, "")
		require.NoError(t, err)
		assert.Len(t, sessions, 1)
		assert.Equal(t, "admin", sessions[0].Name)
	})
}

func TestLoadFromAuthInline(t *testing.T) {
	sessions, err := LoadFromAuthInline([]string{
		"admin:Cookie:session=abc",
		"user2:Authorization:Bearer token123",
	})
	require.NoError(t, err)
	assert.Len(t, sessions, 2)
	assert.Equal(t, "admin", sessions[0].Name)
	assert.Equal(t, "session=abc", sessions[0].Headers["Cookie"])
	assert.Equal(t, "Bearer token123", sessions[1].Headers["Authorization"])
}

func TestLoadFromAuthFilesBareName(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(
		filepath.Join(dir, "myapp.yaml"),
		[]byte("name: myapp\nrole: primary\nheaders:\n  Cookie: sid=xyz\n"),
		0644,
	))

	sessions, err := LoadFromAuthFiles([]string{"myapp"}, dir)
	require.NoError(t, err)
	assert.Len(t, sessions, 1)
	assert.Equal(t, "myapp", sessions[0].Name)
	assert.Equal(t, "sid=xyz", sessions[0].Headers["Cookie"])
}

func TestIsJSON(t *testing.T) {
	assert.True(t, isJSON("config.json", "anything"))
	assert.True(t, isJSON("config.yaml", `{"sessions": []}`))
	assert.True(t, isJSON("config.yaml", `  { "sessions": [] }`))
	assert.False(t, isJSON("config.yaml", "sessions:\n  - name: x"))
	assert.False(t, isJSON("config.yml", ""))
}

func TestResolveSessionPathJSON(t *testing.T) {
	dir := t.TempDir()

	// Create a .json session file in the directory
	require.NoError(t, os.WriteFile(filepath.Join(dir, "my-session.json"), []byte(`{}`), 0644))

	// Should find .json when no .yaml/.yml exists
	resolved := resolveSessionPath("my-session", dir)
	assert.Equal(t, filepath.Join(dir, "my-session.json"), resolved)

	// .yaml takes precedence when both exist
	require.NoError(t, os.WriteFile(filepath.Join(dir, "my-session.yaml"), []byte(`name: x`), 0644))
	resolved = resolveSessionPath("my-session", dir)
	assert.Equal(t, filepath.Join(dir, "my-session.yaml"), resolved)
}

func TestLoadFromAuthInlineRejectsBadFormat(t *testing.T) {
	tests := []string{
		"admin:Cookie",  // missing value
		":Cookie:value", // empty name
		"admin",         // no colons
	}
	for _, in := range tests {
		_, err := LoadFromAuthInline([]string{in})
		assert.Error(t, err, "input=%q should fail", in)
	}
}
