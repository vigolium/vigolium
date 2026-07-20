package fuzz

import (
	"bufio"
	"bytes"
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
}

// PayloadClasses returns the built-in vulnerability-class names accepted by
// LoadPayloads' classes argument (and `vigolium fuzz --class`).
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
		return nil, fmt.Errorf("no payloads: supply -w/--wordlist, --class, or -p/--payload")
	}
	return out, nil
}

func loadWordlist(ref string) ([]string, error) {
	if name, ok := builtinWordlists[ref]; ok {
		data, err := wordlists.WordlistsFS.ReadFile(name)
		if err != nil {
			return nil, fmt.Errorf("read builtin wordlist %q: %w", ref, err)
		}
		return scanLines(data), nil
	}
	data, err := os.ReadFile(ref)
	if err != nil {
		return nil, fmt.Errorf("read wordlist %q (not a builtin %v, and not a readable file): %w", ref, BuiltinNames(), err)
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
