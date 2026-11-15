package fuzz

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/vigolium/vigolium/internal/resources/wordlists"
	"github.com/vigolium/vigolium/pkg/payloads"
)

// builtinWordlists maps a short name to an embedded list file. These ship in
// the binary (internal/resources/wordlists) and are read in-memory here — fuzz
// never needs them on disk, unlike deparos.
var builtinWordlists = map[string]string{
	"fuzz":       "fuzz.txt",
	"dir-short":  "dir-short.txt",
	"dir-long":   "dir-long.txt",
	"file-short": "file-short.txt",
	"file-long":  "file-long.txt",
	// Candidate parameter names, for --fuzz new-param (the list the param
	// mining phase and `kit param-mine` use).
	"params": "params.txt",
}

// PayloadClasses returns the built-in vulnerability-class names accepted by
// LoadPayloads' classes argument (and `vigolium fuzz --class`).
// ErrNoPayloads is a fuzz run given no payload source.
var ErrNoPayloads = errors.New("no payloads: supply -w/--wordlist, --class, or -p/--payload")

func PayloadClasses() []string {
	return payloads.Classes()
}

// BuiltinNames returns the sorted builtin wordlist names for help text.
func BuiltinNames() []string {
	names := make([]string, 0, len(builtinWordlists))
	for n := range builtinWordlists {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// LoadPayloads assembles the payload set from wordlist references, vulnerability
// classes, and inline literals, de-duplicated in first-seen order. A wordlist
// reference is either a builtin name (see BuiltinNames) or a filesystem path; a
// class is a payloads.Classes() name or alias (e.g. "sqli", "traversal"). Blank
// lines and lines beginning with '#' in wordlists are skipped.
func LoadPayloads(wordlistRefs, classes, inline []string) ([]string, error) {
	var out []string
	seen := make(map[string]struct{})
	add := func(p string) {
		if p == "" {
			return
		}
		if _, ok := seen[p]; ok {
			return
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}

	for _, ref := range wordlistRefs {
		lines, err := loadWordlist(ref)
		if err != nil {
			return nil, err
		}
		for _, l := range lines {
			add(l)
		}
	}
	for _, class := range classes {
		list, ok := payloads.ByClass(class)
		if !ok {
			return nil, fmt.Errorf("unknown --class %q; available: %s", class, strings.Join(payloads.Classes(), ", "))
		}
		for _, p := range list {
			add(p)
		}
	}
	for _, p := range inline {
		add(p)
	}

	if len(out) == 0 {
		return nil, ErrNoPayloads
	}
	return out, nil
}

// defaultBuiltinWordlist is the list `-w builtin` and `-w default` name: the
// general fuzz list. Both words are what a reader of the help placeholder
// reaches for, and refusing them sent callers hunting for a file named
// "builtin".
const defaultBuiltinWordlist = "fuzz"

// resolveBuiltinName maps a wordlist reference to a builtin list name, or ""
// when it names none. `builtin:<name>` is the explicit form, and wins over a
// file of the same name.
func resolveBuiltinName(ref string) string {
	if name, ok := strings.CutPrefix(ref, "builtin:"); ok {
		if _, known := builtinWordlists[name]; known {
			return name
		}
		return ""
	}
	switch ref {
	case "builtin", "default":
		return defaultBuiltinWordlist
	}
	if _, ok := builtinWordlists[ref]; ok {
		return ref
	}
	return ""
}

func loadWordlist(ref string) ([]string, error) {
	if strings.HasPrefix(ref, "builtin:") && resolveBuiltinName(ref) == "" {
		return nil, fmt.Errorf("unknown builtin wordlist %q; builtins: %s (or a file path)", ref, strings.Join(BuiltinNames(), ", "))
	}
	if name := resolveBuiltinName(ref); name != "" {
		ref = name
	}
	if name, ok := builtinWordlists[ref]; ok {
		data, err := wordlists.WordlistsFS.ReadFile(name)
		if err != nil {
			return nil, fmt.Errorf("read builtin wordlist %q: %w", ref, err)
		}
		return scanLines(data), nil
	}
	data, err := os.ReadFile(ref)
	if err != nil {
		return nil, fmt.Errorf("read wordlist %q: not a builtin (%s, or builtin/default for %q) and not a readable file: %w",
			ref, strings.Join(BuiltinNames(), ", "), defaultBuiltinWordlist, err)
	}
	return scanLines(data), nil
}

func scanLines(data []byte) []string {
	var lines []string
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, line)
	}
	return lines
}

// ExpandSuffixes returns payloads with, after each word, that word plus each
// suffix appended — ffuf's -e semantics (`admin`, `admin.php`, `admin.bak`).
// Suffixes are appended literally, so pass the dot (".php"). Duplicates are
// dropped in first-seen order; no suffixes returns payloads unchanged.
func ExpandSuffixes(payloads, suffixes []string) []string {
	if len(suffixes) == 0 {
		return payloads
	}
	out := make([]string, 0, len(payloads)*(len(suffixes)+1))
	seen := make(map[string]struct{}, cap(out))
	add := func(p string) {
		if _, ok := seen[p]; ok {
			return
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	for _, p := range payloads {
		add(p)
		for _, s := range suffixes {
			if s != "" {
				add(p + s)
			}
		}
	}
	return out
}
