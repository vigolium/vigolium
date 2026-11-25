package paths

import (
	"os"
	"path/filepath"
	"strings"
)

// StateDirEnv relocates everything vigolium writes. Unset, vigolium keeps its
// state where it always lives under $HOME:
//
//	~/.vigolium/            config, default DB, presets, projects, active-project,
//	                        sessions, native-sessions/, replay jars, markers
//	~/.cache/<name>/        caches (Chrome for Testing, spitolas, jstangle, audit)
//	~/nuclei-templates/     the known-issue templates
//
// Set, every one of those lives under the variable's directory instead:
//
//	$VIGOLIUM_STATE_DIR/                    what ~/.vigolium holds
//	$VIGOLIUM_STATE_DIR/cache/<name>/       what ~/.cache/<name> holds
//	$VIGOLIUM_STATE_DIR/nuclei-templates/   the templates
//	$VIGOLIUM_STATE_DIR/lib/                the embedded nuclei/uncover libraries'
//	                                        config dirs (internal/paths/earlyenv)
//
// so a driver that sets it can run vigolium against a read-only or disposable
// HOME and find every byte vigolium wrote in one tree.
const StateDirEnv = "VIGOLIUM_STATE_DIR"

// StateDirSet reports whether VIGOLIUM_STATE_DIR names a directory.
func StateDirSet() bool { return stateDirOverride() != "" }

// stateDirOverride is VIGOLIUM_STATE_DIR made absolute and clean, "" when
// unset. A relative value is taken against the working directory at the time
// of the call, as every other relative path vigolium reads.
func stateDirOverride() string {
	v := strings.TrimSpace(os.Getenv(StateDirEnv))
	if v == "" {
		return ""
	}
	if abs, err := filepath.Abs(v); err == nil {
		return abs
	}
	return filepath.Clean(v)
}

// VigoliumDir is the directory ~/.vigolium names: VIGOLIUM_STATE_DIR when set,
// else ~/.vigolium. It is "" only when neither the variable nor the home
// directory resolves.
func VigoliumDir() string {
	if d := stateDirOverride(); d != "" {
		return d
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, ".vigolium")
}

// VigoliumPath joins elem under VigoliumDir ("" when that is "").
func VigoliumPath(elem ...string) string {
	dir := VigoliumDir()
	if dir == "" {
		return ""
	}
	return filepath.Join(append([]string{dir}, elem...)...)
}

// UserCacheDir is the cache directory ~/.cache/<name> names:
// $VIGOLIUM_STATE_DIR/cache/<name> when the variable is set. "" when neither
// resolves.
func UserCacheDir(name string) string {
	if d := stateDirOverride(); d != "" {
		return filepath.Join(d, "cache", name)
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, ".cache", name)
}

// NucleiTemplatesDir is the default nuclei templates directory:
// $VIGOLIUM_STATE_DIR/nuclei-templates when the variable is set, else
// ~/nuclei-templates. "" when neither resolves.
func NucleiTemplatesDir() string {
	if d := stateDirOverride(); d != "" {
		return filepath.Join(d, "nuclei-templates")
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, "nuclei-templates")
}

// LibDir is where earlyenv points the embedded libraries' config dirs under
// VIGOLIUM_STATE_DIR ("" when the variable is unset).
func LibDir(elem ...string) string {
	d := stateDirOverride()
	if d == "" {
		return ""
	}
	return filepath.Join(append([]string{d, "lib"}, elem...)...)
}

// homeRelocations maps the home-relative spellings of vigolium's state onto
// the state root. Longest prefix first is not needed: no entry is a prefix of
// another.
var homeRelocations = []struct {
	prefix string // "~/"-relative, no trailing slash
	target func(d string) string
}{
	{".vigolium", func(d string) string { return d }},
	{".cache", func(d string) string { return filepath.Join(d, "cache") }},
	{"nuclei-templates", func(d string) string { return filepath.Join(d, "nuclei-templates") }},
}

// Relocate rewrites a "~/"-relative path that names vigolium state (~/.vigolium,
// ~/.cache, ~/nuclei-templates and anything under them) onto
// VIGOLIUM_STATE_DIR, and returns every other path unchanged. Unset, it is the
// identity, so the caller's "~" expansion applies as before. Config defaults
// spell their paths "~/.vigolium/...", so routing ExpandPath through here moves
// every configured default at once.
func Relocate(p string) string {
	d := stateDirOverride()
	if d == "" {
		return p
	}
	rest, ok := strings.CutPrefix(p, "~/")
	if !ok {
		return p
	}
	for _, r := range homeRelocations {
		if rest == r.prefix || rest == r.prefix+"/" {
			return r.target(d)
		}
		if tail, ok := strings.CutPrefix(rest, r.prefix+"/"); ok {
			return filepath.Join(r.target(d), tail)
		}
	}
	return p
}
