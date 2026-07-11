package secretscan

import (
	"fmt"
	"regexp"

	re2 "github.com/wasilibs/go-re2"
)

// Engine selects the regex backend used to evaluate rule patterns.
type Engine int

const (
	// EngineRE2 (default) uses github.com/wasilibs/go-re2 — Google's RE2 (C++)
	// compiled to WebAssembly (pure Go, no cgo, works on arm64). Identical RE2
	// semantics to stdlib (so it is correct — zero false negatives), and ~10x
	// faster on bodies >~1KB with this complex rule set. A one-time ~350ms
	// compile cost is amortized by the process-wide Default() detector.
	EngineRE2 Engine = iota
	// EngineStdlib uses Go's standard library regexp (RE2). Correctness reference
	// used by tests; ~10x slower than go-re2 here, so not the default.
	EngineStdlib
)

// matcher is the subset of *regexp.Regexp / go-re2 *Regexp the detector relies
// on. Both engines satisfy it with identical signatures.
type matcher interface {
	FindAllSubmatchIndex(b []byte, n int) [][]int
	SubexpNames() []string
	NumSubexp() int
}

func compilePattern(engine Engine, pat string) (matcher, error) {
	switch engine {
	case EngineRE2:
		re, err := re2.Compile(pat)
		if err != nil {
			return nil, err
		}
		return re, nil
	case EngineStdlib:
		re, err := regexp.Compile(pat)
		if err != nil {
			return nil, err
		}
		return re, nil
	default:
		return nil, fmt.Errorf("secretscan: unknown engine %d", engine)
	}
}
