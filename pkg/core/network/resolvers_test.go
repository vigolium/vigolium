package network

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// SAFE-11: with resolv.conf naming nameservers, no public base resolvers are
// added (internal names never leak to 1.1.1.1 / 8.8.8.8).
func TestBaseResolvers_NoPublicWhenSystemResolversExist(t *testing.T) {
	dir := t.TempDir()
	conf := filepath.Join(dir, "resolv.conf")
	if err := os.WriteFile(conf, []byte("# corp\nnameserver 10.0.0.2\nnameserver 10.0.0.3\nsearch corp.local\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RESOLVERS_PATH", conf)
	if n := systemResolverCount(resolvConfPath()); n != 2 {
		t.Fatalf("systemResolverCount = %d, want 2", n)
	}
	defaults := []string{"1.1.1.1:53", "8.8.8.8:53"}
	got := baseResolvers(nil, systemResolverCount(resolvConfPath()), defaults)
	if slices.Contains(got, "1.1.1.1:53") || len(got) != 0 {
		t.Errorf("base resolvers = %v, want none (system resolvers present)", got)
	}
	if got := baseResolvers(nil, 0, defaults); !slices.Equal(got, defaults) {
		t.Errorf("no system resolvers: base = %v, want the public defaults", got)
	}
	if got := baseResolvers([]string{"9.9.9.9:53"}, 2, defaults); !slices.Equal(got, []string{"9.9.9.9:53"}) {
		t.Errorf("explicit resolvers must win, got %v", got)
	}
}
