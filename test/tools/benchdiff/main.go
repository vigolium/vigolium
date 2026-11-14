// Command benchdiff compares two benchmark result files written by the
// detection benchmark harness ($BENCH_OUT, one JSON object per line; see
// test/benchmark/harness/bench_out.go) and reports what changed per
// (case, module): pass/fail, finding counts and request counts.
//
// It exits 1 when HEAD regresses against BASE: a case that passed now fails,
// a case that found something now finds less, or a case disappeared. Request
// growth beyond the tolerance is reported but only fails with -strict-requests.
//
//	go run ./test/tools/benchdiff -base base.jsonl -head head.jsonl
//	make bench-diff BASE=base.jsonl HEAD=head.jsonl
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"sort"
)

// record mirrors harness.BenchRecord (kept local so this tool does not link
// the whole module registry).
type record struct {
	Commit     string `json:"commit"`
	CaseID     string `json:"case_id"`
	Module     string `json:"module"`
	Assertion  string `json:"assertion"`
	Findings   int    `json:"findings"`
	Requests   int64  `json:"requests"`
	DurationMs int64  `json:"duration_ms"`
	Passed     bool   `json:"passed"`
}

func (r record) key() string { return r.CaseID + " / " + r.Module }

func main() {
	base := flag.String("base", "", "baseline BENCH_OUT file (JSON lines)")
	head := flag.String("head", "", "candidate BENCH_OUT file (JSON lines)")
	tol := flag.Float64("request-tolerance", 0.25, "relative request-count change reported as a drift")
	strictReq := flag.Bool("strict-requests", false, "treat request drift beyond the tolerance as a regression")
	flag.Parse()
	if *base == "" || *head == "" {
		fmt.Fprintln(os.Stderr, "usage: benchdiff -base FILE -head FILE")
		os.Exit(2)
	}
	b, err := load(*base)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	h, err := load(*head)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if regressions := diff(os.Stdout, b, h, *tol, *strictReq); regressions > 0 {
		_, _ = fmt.Fprintf(os.Stdout, "\n%d regression(s)\n", regressions)
		os.Exit(1)
	}
}

// load reads a JSON-lines file. When a (case, module) appears more than once
// (a rerun appended to the same file) the last line wins.
func load(path string) (map[string]record, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return parse(f)
}

func parse(r io.Reader) (map[string]record, error) {
	out := make(map[string]record)
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	line := 0
	for sc.Scan() {
		line++
		if len(sc.Bytes()) == 0 {
			continue
		}
		var rec record
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			return nil, fmt.Errorf("line %d: %w", line, err)
		}
		out[rec.key()] = rec
	}
	return out, sc.Err()
}

// diff writes a per-key change report and returns the number of regressions.
func diff(w io.Writer, base, head map[string]record, tol float64, strictRequests bool) int {
	keys := make(map[string]struct{}, len(base)+len(head))
	for k := range base {
		keys[k] = struct{}{}
	}
	for k := range head {
		keys[k] = struct{}{}
	}
	sorted := make([]string, 0, len(keys))
	for k := range keys {
		sorted = append(sorted, k)
	}
	sort.Strings(sorted)

	regressions := 0
	for _, k := range sorted {
		b, inBase := base[k]
		h, inHead := head[k]
		switch {
		case !inHead:
			regressions++
			_, _ = fmt.Fprintf(w, "REGRESSION %s: missing from head\n", k)
			continue
		case !inBase:
			_, _ = fmt.Fprintf(w, "new        %s: passed=%v findings=%d requests=%d\n", k, h.Passed, h.Findings, h.Requests)
			continue
		}
		if b.Passed && !h.Passed {
			regressions++
			_, _ = fmt.Fprintf(w, "REGRESSION %s: passed -> failed (findings %d -> %d)\n", k, b.Findings, h.Findings)
		} else if !b.Passed && h.Passed {
			_, _ = fmt.Fprintf(w, "fixed      %s: failed -> passed\n", k)
		}
		if h.Findings < b.Findings && h.Assertion != "negative" {
			regressions++
			_, _ = fmt.Fprintf(w, "REGRESSION %s: findings %d -> %d\n", k, b.Findings, h.Findings)
		} else if h.Findings != b.Findings {
			_, _ = fmt.Fprintf(w, "changed    %s: findings %d -> %d\n", k, b.Findings, h.Findings)
		}
		if drifted(b.Requests, h.Requests, tol) {
			label := "requests  "
			if strictRequests && h.Requests > b.Requests {
				regressions++
				label = "REGRESSION"
			}
			_, _ = fmt.Fprintf(w, "%s %s: requests %d -> %d\n", label, k, b.Requests, h.Requests)
		}
	}
	return regressions
}

func drifted(base, head int64, tol float64) bool {
	if base == head {
		return false
	}
	allowed := math.Max(float64(base)*tol, 2)
	return math.Abs(float64(head-base)) > allowed
}
