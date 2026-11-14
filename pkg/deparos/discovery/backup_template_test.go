package discovery

import (
	"slices"
	"testing"

	"github.com/vigolium/vigolium/pkg/deparos/config"
)

func TestExpandBackupTemplate(t *testing.T) {
	cases := []struct{ tmpl, n, e, want string }{
		{"{f}~", "x", "php", "x.php~"},
		{"{n}.bak", "x", "php", "x.bak"},
		{".{f}.swp", "x", "php", ".x.php.swp"},
		{"{n}_old.{e}", "x", "php", "x_old.php"},
		{"bak", "x", "php", "x.php.bak"},  // legacy bare suffix
		{"~1", "x", "php", "x.php.~1"},    // legacy bare suffix
		{"{n}_old.{e}", "config", "", ""}, // needs an extension
		{"{f}.bak", "config", "", "config.bak"},
		{"../{f}", "x", "php", ""}, // never leaves the directory
	}
	for _, c := range cases {
		if got := ExpandBackupTemplate(c.tmpl, c.n, c.e); got != c.want {
			t.Errorf("ExpandBackupTemplate(%q, %q, %q) = %q, want %q", c.tmpl, c.n, c.e, got, c.want)
		}
	}
}

// MISS-6: the default variant set reaches x.php~ and x.bak, which appending
// every variant after a dot never produced.
func TestExtensionVariantTask_DefaultTemplates(t *testing.T) {
	cfg := factoryTestConfig()
	cfg.Extensions.BackupExtensions = config.DefaultBackupExtensions
	task := NewFactory(cfg).CreateExtensionVariantTask([]byte("x.php"), []byte("http://example.com"), []byte("/admin/"), 1)
	if task == nil {
		t.Fatal("no variant task")
	}
	urls := collectURLs(t, task)
	for _, want := range []string{
		"http://example.com/admin/x.php~",
		"http://example.com/admin/x.bak",
		"http://example.com/admin/.x.php.swp",
		"http://example.com/admin/x_old.php",
	} {
		if !slices.Contains(urls, want) {
			t.Errorf("missing %s", want)
		}
	}
}
