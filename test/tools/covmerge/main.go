// Command covmerge merges multiple Go coverage profiles into one.
//
// Go's `go test -coverprofile` writes the legacy text coverage format, which
// `go tool covdata` (the GOCOVERDIR merger) does not consume. When we collect
// coverage from more than one `go test` invocation — e.g. the fast unit slice
// plus the no-Docker e2e tier (see `make coverage-combined`) — we need to fold
// the per-block counts together so a statement covered by either run counts as
// covered.
//
// Merge rule: for each unique coverage block (file + line/col range) keep the
// MAXIMUM count seen across inputs. For `set` mode that is a logical OR (0/1);
// for `count`/`atomic` mode max is a conservative, non-inflating combine that
// never double-counts a block that both runs executed. All inputs must share
// the same mode line.
//
// Usage:
//
//	covmerge -o combined.out a.out b.out [c.out ...]
package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
)

func main() {
	out := flag.String("o", "", "output profile path (default: stdout)")
	flag.Parse()
	inputs := flag.Args()
	if len(inputs) == 0 {
		fmt.Fprintln(os.Stderr, "covmerge: need at least one input profile")
		os.Exit(2)
	}

	mode := ""
	// block key ("file:range numstmt") -> max count
	counts := map[string]int{}
	// preserve a stable key set for deterministic output
	keys := []string{}
	seen := map[string]bool{}

	for _, in := range inputs {
		m, err := mergeFile(in, counts, &keys, seen)
		if err != nil {
			// A missing input is tolerated (a leg may have been skipped); a
			// malformed one is fatal so we never emit a silently-wrong report.
			if os.IsNotExist(err) {
				fmt.Fprintf(os.Stderr, "covmerge: skipping missing %s\n", in)
				continue
			}
			fmt.Fprintf(os.Stderr, "covmerge: %s: %v\n", in, err)
			os.Exit(1)
		}
		if mode == "" {
			mode = m
		} else if m != "" && m != mode {
			fmt.Fprintf(os.Stderr, "covmerge: mode mismatch (%q vs %q in %s)\n", mode, m, in)
			os.Exit(1)
		}
	}

	if mode == "" {
		fmt.Fprintln(os.Stderr, "covmerge: no usable input profiles")
		os.Exit(1)
	}

	w := os.Stdout
	if *out != "" {
		f, err := os.Create(*out)
		if err != nil {
			fmt.Fprintf(os.Stderr, "covmerge: %v\n", err)
			os.Exit(1)
		}
		defer func() { _ = f.Close() }()
		w = f
	}

	bw := bufio.NewWriter(w)
	if _, err := fmt.Fprintf(bw, "mode: %s\n", mode); err != nil {
		fmt.Fprintf(os.Stderr, "covmerge: write: %v\n", err)
		os.Exit(1)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if _, err := fmt.Fprintf(bw, "%s %d\n", k, counts[k]); err != nil {
			fmt.Fprintf(os.Stderr, "covmerge: write: %v\n", err)
			os.Exit(1)
		}
	}
	if err := bw.Flush(); err != nil {
		fmt.Fprintf(os.Stderr, "covmerge: flush: %v\n", err)
		os.Exit(1)
	}
}

// mergeFile folds one profile into counts, returning its mode line value.
func mergeFile(path string, counts map[string]int, keys *[]string, seen map[string]bool) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 1<<24)
	mode := ""
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "mode:") {
			mode = strings.TrimSpace(strings.TrimPrefix(line, "mode:"))
			continue
		}
		// Format: <file>:<startLine>.<col>,<endLine>.<col> <numStmt> <count>
		idx := strings.LastIndexByte(line, ' ')
		if idx < 0 {
			return mode, fmt.Errorf("malformed line: %q", line)
		}
		key := line[:idx] // "<file:range> <numStmt>"
		count, err := strconv.Atoi(line[idx+1:])
		if err != nil {
			return mode, fmt.Errorf("bad count in %q: %w", line, err)
		}
		if cur, ok := counts[key]; !ok {
			counts[key] = count
			if !seen[key] {
				seen[key] = true
				*keys = append(*keys, key)
			}
		} else if count > cur {
			counts[key] = count
		}
	}
	return mode, sc.Err()
}
