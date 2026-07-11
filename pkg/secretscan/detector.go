// Package secretscan is vigolium's native, binary-free secret detector. It
// replaces the former external kingfisher subprocess with an in-process engine
// driven by the normalized kingfisher rule catalog (see pkg/secretscan/catalog
// and pkg/secretscan/secretgen). Detection is regex-based with a keyword prefilter,
// Shannon-entropy and character-class gating, and a benign-placeholder safelist —
// faithfully mirroring kingfisher's matcher semantics. Live secret VERIFICATION
// is intentionally not performed.
package secretscan

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/coregx/ahocorasick"
	lru "github.com/hashicorp/golang-lru/v2"

	"github.com/vigolium/vigolium/pkg/secretscan/catalog"
)

// defaultMaxMatchesPerRule bounds how many *accepted* matches a single rule
// reports per body. It caps output size (redundant Additional Evidence) without
// deciding which matches are inspected — see rawMatchCeilingFactor.
const defaultMaxMatchesPerRule = 100

// rawMatchCeilingFactor sets how many raw regex matches a rule may enumerate per
// body relative to its accepted cap, before gating. Accepting only the first
// MaxMatchesPerRule matches that PASS the entropy/character/safelist gates (not
// merely the first MaxMatchesPerRule raw matches) means a real credential is not
// hidden behind a flood of gated-out placeholders earlier in the body. The raw
// ceiling still bounds cost on a pathological body a generic rule matches
// thousands of times: enumeration stops at MaxMatchesPerRule*rawMatchCeilingFactor
// raw hits, and the common accept-heavy case breaks out at the accepted cap long
// before reaching it.
const rawMatchCeilingFactor = 10

// Options configures a Detector.
type Options struct {
	// IncludeInvisible enables rules marked visible:false in the catalog
	// (kingfisher's noisy/experimental set). Off by default.
	IncludeInvisible bool
	// MaxMatchesPerRule caps ACCEPTED matches per rule per body (<=0 → default).
	MaxMatchesPerRule int
	// Engine selects the regex backend (zero value = EngineRE2 / go-re2).
	Engine Engine
	// BodyCacheSize bounds the per-body result cache (keyed by body SHA-256).
	// A value >0 enables caching; 0 leaves the caller default (Default enables
	// it, New leaves it off); <0 disables it explicitly. Hashing a body is far
	// cheaper than scanning it, so repeated identical bodies (SPA shells, records
	// re-seen across scan passes) are served from cache. Safe: Detect is a pure
	// function of (rule set, body).
	BodyCacheSize int
	// UseRegexSet enables the experimental compiled-regex Set prefilter
	// (setprefilter.go): the body is scanned once by a sharded go-re2 Set to learn
	// which rule patterns can match at all, and only those rules' capture regexes
	// are run. Off by default — it layers on top of the keyword prefilter and its
	// benefit is workload-dependent, so it ships benchmarked and opt-in. If the
	// set fails to compile, detection falls back to the keyword prefilter alone.
	UseRegexSet bool
	// RegexSetShardSize is the number of patterns per Set shard when UseRegexSet is
	// on (<=0 → default). A large single set may exceed go-re2's program-size
	// limit, so patterns are compiled into shards.
	RegexSetShardSize int
}

// Match is a single detected secret.
type Match struct {
	RuleID     string
	RuleName   string
	Source     string  // rule source; always "kingfisher"
	Confidence string  // "high" | "medium" | "low"
	Pattern    string  // the rule's normalized RE2 pattern that fired (for evidence)
	Secret     string  // the selected secret capture
	Start      int     // byte offset of the secret in the scanned input
	End        int     // exclusive end offset
	Entropy    float64 // computed Shannon entropy (bits/byte) of the secret
}

type compiledRule struct {
	rule        catalog.Rule
	re          matcher
	secretCands []int // candidate capture indices, tried in priority order per match
	reqUseFull  bool  // apply character requirements to the full match vs. secret
}

// Detector holds the compiled rule set and keyword prefilter.
type Detector struct {
	rules      []compiledRule
	ac         *ahocorasick.Automaton
	kwToRules  [][]int  // AC pattern id -> candidate rule indices
	kwList     []string // AC pattern id -> keyword (parallel to kwToRules)
	alwaysRun  []int    // rule indices with no keyword (always evaluated)
	maxPerRule int      // accepted-match cap per rule per body
	rawCeiling int      // raw-match enumeration cap per rule (>= maxPerRule)

	// cache memoizes Detect results keyed by body SHA-256. nil when disabled.
	// *lru.Cache is safe for concurrent use, preserving Detect's concurrency
	// contract. Detect is a pure function of (rule set, body), so a cached result
	// is always valid for an identical body.
	cache *lru.Cache[[sha256.Size]byte, []Match]

	// set is the optional compiled-regex Set prefilter (see setprefilter.go). nil
	// unless Options.UseRegexSet is enabled and the set compiled. When present,
	// Detect uses it to drop candidate rules whose pattern cannot match the body
	// before running their capture regex.
	set *regexSet
}

// New compiles a Detector from a catalog. Regex compilation happens once here;
// callers should reuse the Detector across scans (see Default).
func New(cat *catalog.Catalog, opts Options) (*Detector, error) {
	if cat == nil {
		return nil, fmt.Errorf("secretscan: nil catalog")
	}
	maxPer := opts.MaxMatchesPerRule
	if maxPer <= 0 {
		maxPer = defaultMaxMatchesPerRule
	}

	d := &Detector{maxPerRule: maxPer, rawCeiling: maxPer * rawMatchCeilingFactor}

	if opts.BodyCacheSize > 0 {
		// lru.New only errors on a non-positive size; guarded above, so the
		// ignored error is provably nil.
		d.cache, _ = lru.New[[sha256.Size]byte, []Match](opts.BodyCacheSize)
	}

	kwIndex := map[string][]int{} // keyword -> rule indices
	var kwOrder []string          // stable keyword ordering for the AC

	for _, r := range cat.Rules {
		if !r.Visible && !opts.IncludeInvisible {
			continue
		}
		re, err := compilePattern(opts.Engine, r.Re)
		if err != nil {
			// A catalog rule that fails at runtime is a generation bug; skip it
			// rather than fail the whole scanner. secretgen already compile-checks.
			continue
		}
		cr := compiledRule{rule: r, re: re}
		cr.secretCands, cr.reqUseFull = resolveCapture(re, r.SecretGroup)
		idx := len(d.rules)
		d.rules = append(d.rules, cr)

		if len(r.Kw) == 0 {
			d.alwaysRun = append(d.alwaysRun, idx)
			continue
		}
		for _, kw := range r.Kw {
			kw = strings.ToLower(kw)
			if kw == "" {
				continue
			}
			if _, ok := kwIndex[kw]; !ok {
				kwOrder = append(kwOrder, kw)
			}
			kwIndex[kw] = append(kwIndex[kw], idx)
		}
	}

	// Build the Aho-Corasick prefilter over the deduplicated keyword set.
	if len(kwOrder) > 0 {
		builder := ahocorasick.NewBuilder().SetASCII(true)
		builder.AddStrings(kwOrder)
		ac, err := builder.Build()
		if err != nil {
			return nil, fmt.Errorf("secretscan: build keyword prefilter: %w", err)
		}
		d.ac = ac
		d.kwList = kwOrder
		d.kwToRules = make([][]int, len(kwOrder))
		for i, kw := range kwOrder {
			d.kwToRules[i] = kwIndex[kw]
		}
	}

	// Optional compiled-regex Set prefilter. Built last so it sees every compiled
	// rule; a compile failure leaves d.set nil (keyword prefilter only).
	if opts.UseRegexSet {
		d.set = buildRegexSet(d.rules, opts.RegexSetShardSize)
	}

	return d, nil
}

// resolveCapture builds the ordered list of candidate capture indices for "the
// secret", mirroring kingfisher's find_secret_capture, plus whether character
// requirements apply to the full match. Selection is finalized per match in
// pickSecret because kingfisher prefers the first named group that actually
// participated — an optional named group that didn't match is skipped.
func resolveCapture(re matcher, explicit int) (cands []int, reqUseFull bool) {
	names := re.SubexpNames() // index 0 == whole match, "" for unnamed
	n := re.NumSubexp()       // capturing groups, excluding group 0

	// Character requirements: kingfisher uses the full match when there are named
	// captures OR more than one capturing group; otherwise the secret span.
	hasNamed := false
	for i := 1; i < len(names); i++ {
		if names[i] != "" {
			hasNamed = true
			break
		}
	}
	reqUseFull = hasNamed || n > 1

	// An explicit positional secret_group override is tried first (dormant — no
	// current kingfisher rule sets it — but honored for schema completeness).
	if explicit > 0 && explicit <= n {
		cands = append(cands, explicit)
	}
	// 1. named capture "TOKEN" (case-insensitive)
	for i := 1; i < len(names); i++ {
		if strings.EqualFold(names[i], "TOKEN") {
			cands = append(cands, i)
		}
	}
	// 2. other named captures, in pattern order
	for i := 1; i < len(names); i++ {
		if names[i] != "" && !strings.EqualFold(names[i], "TOKEN") {
			cands = append(cands, i)
		}
	}
	// 3. first positional capture
	if n >= 1 {
		cands = append(cands, 1)
	}
	// 4. whole match
	cands = append(cands, 0)
	return dedupInts(cands), reqUseFull
}

func dedupInts(in []int) []int {
	seen := map[int]struct{}{}
	out := in[:0]
	for _, v := range in {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

// pickSecret returns the span of the first candidate capture that participated
// in this match, matching kingfisher's runtime find_secret_capture behavior.
func pickSecret(loc []int, cands []int) (int, int) {
	for _, c := range cands {
		s, e := groupSpan(loc, c)
		if s >= 0 && e >= s {
			return s, e
		}
	}
	return -1, -1
}

// Detect scans data and returns all secrets found. Safe for concurrent use.
//
// When the body-SHA cache is enabled, an identical body short-circuits to its
// previously computed matches — Detect is a pure function of (rule set, body), so
// a cached result is always valid. The returned slice is treated as read-only by
// all callers; it may be shared with concurrent callers of the same body.
func (d *Detector) Detect(data []byte) []Match {
	if len(data) == 0 || len(d.rules) == 0 {
		return nil
	}

	if d.cache == nil {
		return d.detect(data)
	}

	// Hashing the body is dramatically cheaper than scanning it (~GB/s vs the
	// rule set's ~MB/s), so identical bodies (repeated SPA shells, the same page
	// re-fetched across discovery/spider/assessment passes, historical DB records)
	// are served from cache instead of rescanned.
	key := sha256.Sum256(data)
	if cached, ok := d.cache.Get(key); ok {
		return cached
	}
	matches := d.detect(data)
	d.cache.Add(key, matches)
	return matches
}

// detect runs the uncached detection pipeline over data.
func (d *Detector) detect(data []byte) []Match {
	// Candidate rule set = keyword hits (prefilter) ∪ always-run rules.
	candidates := make(map[int]struct{}, len(d.alwaysRun)+16)
	for _, idx := range d.alwaysRun {
		candidates[idx] = struct{}{}
	}
	if d.ac != nil {
		lower := bytes.ToLower(data)
		for _, m := range d.ac.FindAllOverlapping(lower) {
			for _, idx := range d.kwToRules[m.PatternID] {
				candidates[idx] = struct{}{}
			}
		}
	}

	// Optional compiled-regex Set prefilter: drop candidate rules whose pattern
	// cannot match the body at all, sparing their capture regex a full-body scan.
	if d.set != nil {
		d.set.retain(data, candidates)
	}

	var matches []Match
	for idx := range candidates {
		cr := &d.rules[idx]
		// Enumerate up to rawCeiling raw matches, but keep only the first
		// maxPerRule that pass the entropy/character/safelist gates (see
		// rawMatchCeilingFactor). Capping ACCEPTED matches — not raw ones — means a
		// real credential is not hidden behind a flood of gated-out placeholders
		// earlier in the body; the accept-cap break keeps the common case as cheap
		// as the old raw cap.
		locs := cr.re.FindAllSubmatchIndex(data, d.rawCeiling)
		accepted := 0
		for _, loc := range locs {
			ss, se := pickSecret(loc, cr.secretCands)
			if ss < 0 || se > len(data) || ss >= se {
				continue
			}
			secret := data[ss:se]

			// Entropy gate: strictly greater than the threshold (kingfisher).
			ent := shannonEntropyBits(secret)
			if cr.rule.Entropy > 0 && ent <= cr.rule.Entropy {
				continue
			}

			// Character-requirement gate on the appropriate span.
			reqStart, reqEnd := ss, se
			if cr.reqUseFull {
				reqStart, reqEnd = loc[0], loc[1]
			}
			if !meetsCharReqs(data[reqStart:reqEnd], cr.rule) {
				continue
			}

			// Benign-placeholder safelist, applied to the secret capture only
			// (matching kingfisher's is_safe_match on entropy_bytes).
			if isBenign(secret) {
				continue
			}

			matches = append(matches, Match{
				RuleID:     cr.rule.ID,
				RuleName:   cr.rule.Name,
				Source:     cr.rule.Src,
				Confidence: cr.rule.Confidence,
				Pattern:    cr.rule.Re,
				Secret:     string(secret),
				Start:      ss,
				End:        se,
				Entropy:    ent,
			})
			accepted++
			if accepted >= d.maxPerRule {
				break
			}
		}
	}

	return dedupeMatches(matches)
}

// RuleCount returns the number of active compiled rules.
func (d *Detector) RuleCount() int { return len(d.rules) }

func groupSpan(loc []int, group int) (int, int) {
	i := 2 * group
	if i+1 >= len(loc) {
		return -1, -1
	}
	return loc[i], loc[i+1]
}

// meetsCharReqs enforces min_digits / min_lowercase / min_uppercase /
// min_special_chars on the validated span. Special = non-alphanumeric.
func meetsCharReqs(b []byte, r catalog.Rule) bool {
	if r.MinDigits == 0 && r.MinLower == 0 && r.MinUpper == 0 && r.MinSpecial == 0 {
		return true
	}
	var digits, lower, upper, special int
	for _, c := range b {
		switch {
		case c >= '0' && c <= '9':
			digits++
		case c >= 'a' && c <= 'z':
			lower++
		case c >= 'A' && c <= 'Z':
			upper++
		default:
			special++
		}
	}
	return digits >= r.MinDigits && lower >= r.MinLower && upper >= r.MinUpper && special >= r.MinSpecial
}

// shannonEntropyBits returns Shannon entropy in bits/byte (0–8) over the byte
// distribution — identical to kingfisher's calculate_shannon_entropy and
// vigolium's infra.ShannonEntropyBits, so ported thresholds transfer 1:1.
func shannonEntropyBits(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	var counts [256]int
	for _, c := range b {
		counts[c]++
	}
	n := float64(len(b))
	var h float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}

// confidenceRank orders confidences for dedupe (higher wins).
func confidenceRank(c string) int {
	switch c {
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

// dedupeMatches collapses matches that cover the same secret at an overlapping
// span (e.g. two kingfisher rules both firing on one key), keeping the
// highest-confidence rule. Distinct occurrences at non-overlapping offsets are
// preserved.
func dedupeMatches(in []Match) []Match {
	if len(in) <= 1 {
		return in
	}
	sort.Slice(in, func(i, j int) bool {
		if in[i].Start != in[j].Start {
			return in[i].Start < in[j].Start
		}
		if confidenceRank(in[i].Confidence) != confidenceRank(in[j].Confidence) {
			return confidenceRank(in[i].Confidence) > confidenceRank(in[j].Confidence)
		}
		return in[i].RuleID < in[j].RuleID
	})
	kept := in[:0]
	for _, m := range in {
		dup := false
		for k := len(kept) - 1; k >= 0; k-- {
			p := kept[k]
			if p.End <= m.Start { // sorted by Start; no earlier kept can overlap
				break
			}
			if p.Secret == m.Secret && spansOverlap(p.Start, p.End, m.Start, m.End) {
				dup = true
				break
			}
		}
		if !dup {
			kept = append(kept, m)
		}
	}
	return kept
}

func spansOverlap(aStart, aEnd, bStart, bEnd int) bool {
	return aStart < bEnd && bStart < aEnd
}
