package paths

import (
	"path/filepath"
	"testing"
)

func TestStateDirUnsetKeepsHomeLayout(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv(StateDirEnv, "")

	if StateDirSet() {
		t.Fatal("StateDirSet with the variable empty")
	}
	for got, want := range map[string]string{
		VigoliumDir():               filepath.Join(home, ".vigolium"),
		VigoliumPath("replay-jars"): filepath.Join(home, ".vigolium", "replay-jars"),
		UserCacheDir("vigolium"):    filepath.Join(home, ".cache", "vigolium"),
		NucleiTemplatesDir():        filepath.Join(home, "nuclei-templates"),
		LibDir("nuclei"):            "",
	} {
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	}
	if got := Relocate("~/.vigolium/x"); got != "~/.vigolium/x" {
		t.Errorf("Relocate without the variable = %q, want it unchanged", got)
	}
}

func TestStateDirRelocatesEveryStatePath(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	state := t.TempDir()
	t.Setenv(StateDirEnv, state)

	if !StateDirSet() {
		t.Fatal("StateDirSet false with the variable set")
	}
	checks := []struct{ got, want string }{
		{VigoliumDir(), state},
		{VigoliumPath("native-sessions"), filepath.Join(state, "native-sessions")},
		{UserCacheDir("vigolium"), filepath.Join(state, "cache", "vigolium")},
		{NucleiTemplatesDir(), filepath.Join(state, "nuclei-templates")},
		{LibDir("nuclei"), filepath.Join(state, "lib", "nuclei")},
		{Relocate("~/.vigolium"), state},
		{Relocate("~/.vigolium/"), state},
		{Relocate("~/.vigolium/vigolium-configs.yaml"), filepath.Join(state, "vigolium-configs.yaml")},
		{Relocate("~/.vigolium/database-vgnm.sqlite"), filepath.Join(state, "database-vgnm.sqlite")},
		{Relocate("~/.cache/vigolium/chrome-for-testing-1"), filepath.Join(state, "cache", "vigolium", "chrome-for-testing-1")},
		{Relocate("~/nuclei-templates"), filepath.Join(state, "nuclei-templates")},
		// Not vigolium state: left for the caller's own ~ expansion.
		{Relocate("~/.vigolium-other/x"), "~/.vigolium-other/x"},
		{Relocate("~/work/app"), "~/work/app"},
		{Relocate("/abs/.vigolium/x"), "/abs/.vigolium/x"},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("got %q, want %q", c.got, c.want)
		}
	}
}

func TestStateDirRelativeIsMadeAbsolute(t *testing.T) {
	wd := t.TempDir()
	t.Chdir(wd)
	t.Setenv(StateDirEnv, "state")
	want, _ := filepath.Abs("state")
	if got := VigoliumDir(); got != want {
		t.Fatalf("VigoliumDir = %q, want %q", got, want)
	}
}
