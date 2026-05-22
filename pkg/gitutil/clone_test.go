package gitutil

import (
	"net/url"
	"strings"
	"testing"
)

func TestLooksLikeGitURL(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"https://github.com/org/repo", true},
		{"http://example.com/repo.git", true},
		{"git@github.com:org/repo.git", true},
		{"/local/path/to/repo", false},
		{"./relative", false},
		{"github.com/org/repo", false}, // no scheme
		{"", false},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := LooksLikeGitURL(tt.in); got != tt.want {
				t.Errorf("LooksLikeGitURL(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestGitURLToDirName(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{"https", "https://github.com/juice-shop/juice-shop", "github.com_juice-shop_juice-shop", false},
		{"https with .git", "https://github.com/org/repo.git", "github.com_org_repo", false},
		{"ssh git@", "git@github.com:org/repo.git", "github.com_org_repo", false},
		{"nested path", "https://gitlab.com/group/subgroup/repo", "gitlab.com_group_subgroup_repo", false},
		{"no path", "https://github.com", "", true},
		{"no path trailing slash", "https://github.com/", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GitURLToDirName(tt.in)
			if (err != nil) != tt.wantErr {
				t.Fatalf("GitURLToDirName(%q) err = %v, wantErr %v", tt.in, err, tt.wantErr)
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("GitURLToDirName(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestInjectToken(t *testing.T) {
	t.Run("https injects userinfo", func(t *testing.T) {
		got, err := injectToken("https://github.com/org/repo.git", "secret-token")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		u, perr := url.Parse(got)
		if perr != nil {
			t.Fatalf("result not a valid URL: %v", perr)
		}
		if u.User.Username() != "x-access-token" {
			t.Errorf("username = %q, want x-access-token", u.User.Username())
		}
		pw, _ := u.User.Password()
		if pw != "secret-token" {
			t.Errorf("password = %q, want secret-token", pw)
		}
		if u.Host != "github.com" {
			t.Errorf("host = %q, want github.com", u.Host)
		}
	})

	t.Run("http scheme also injects", func(t *testing.T) {
		got, err := injectToken("http://example.com/org/repo.git", "tok")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.Contains(got, "x-access-token:tok@") {
			t.Errorf("expected token injected into http URL, got %q", got)
		}
	})

	t.Run("parseable non-http scheme passes through unchanged", func(t *testing.T) {
		// ssh:// parses cleanly but is not http(s), so the token must not be
		// injected (it would otherwise leak the token into an SSH URL).
		in := "ssh://git@github.com/org/repo.git"
		got, err := injectToken(in, "token")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != in {
			t.Errorf("ssh URL should pass through unchanged, got %q", got)
		}
	})
}
