package secretscan

import (
	"github.com/wasilibs/go-re2/experimental"
)

// defaultRegexSetShardSize is the number of rule patterns compiled into one
// go-re2 Set shard. RE2 caps a program's compiled size, and the full rule set is
// far too large for a single Set, so patterns are sharded. 128 is a starting
// point; benchmark 64/128/256 (see setprefilter_bench_test.go) for a given build.
const defaultRegexSetShardSize = 128

// regexSet is the optional compiled-regex Set prefilter. It compiles every rule's
// pattern into sharded go-re2 experimental Sets. A single pass per shard over a
// body reports which rules' patterns can match at all; Detect then drops
// candidate rules the Set rules out before running their (more expensive) capture
// regex.
//
// Soundness: the Set is compiled from the exact same pattern strings the detector
// compiles per rule, so "the Set matches pattern P" ⟺ "rule P's regex matches".
// Pruning a rule the Set rules out therefore removes zero real matches — it only
// skips a regex that was guaranteed to find nothing. The entropy/character/
// safelist gates and capture extraction are unaffected (they run afterward on the
// surviving rules exactly as before).
//
// Experimental and opt-in (Options.UseRegexSet): the go-re2 Set API carries no
// stability guarantee, and its benefit over the keyword prefilter is
// workload-dependent. go-re2 match objects are safe for concurrent use (the
// detector already scans shared compiled rules from the executor's worker pool),
// and Set rides the same ABI, so retain needs no additional locking.
type regexSet struct {
	shards []*regexSetShard
	// ruleShard maps a global rule index to the shard holding it, or -1 when the
	// rule is in no shard (its shard failed to compile) and so can't be pruned.
	// A dense slice beats a set here: it doubles as the is-covered test and the
	// candidate→shard bucketing in retain.
	ruleShard []int
}

type regexSetShard struct {
	set     *experimental.Set
	ruleIdx []int // set-local pattern index -> global rule index
}

// buildRegexSet compiles the rule patterns into sharded Sets. A shard that fails
// to compile (e.g. a pattern go-re2's Set rejects, or a shard exceeding the RE2
// program-size limit) is skipped: its rules are simply never pruned (left as
// always-considered candidates), so a compile failure degrades performance, never
// correctness. Returns nil when no shard compiles, leaving the detector on the
// keyword prefilter alone.
func buildRegexSet(rules []compiledRule, shardSize int) *regexSet {
	if len(rules) == 0 {
		return nil
	}
	if shardSize <= 0 {
		shardSize = defaultRegexSetShardSize
	}

	ruleShard := make([]int, len(rules))
	for i := range ruleShard {
		ruleShard[i] = -1
	}
	rs := &regexSet{ruleShard: ruleShard}
	for start := 0; start < len(rules); start += shardSize {
		end := start + shardSize
		if end > len(rules) {
			end = len(rules)
		}
		exprs := make([]string, 0, end-start)
		ruleIdx := make([]int, 0, end-start)
		for i := start; i < end; i++ {
			exprs = append(exprs, rules[i].rule.Re)
			ruleIdx = append(ruleIdx, i)
		}
		set, err := experimental.CompileSet(exprs)
		if err != nil {
			// Skip this shard; its rules stay unprunable (correct, just slower).
			continue
		}
		shardPos := len(rs.shards)
		rs.shards = append(rs.shards, &regexSetShard{set: set, ruleIdx: ruleIdx})
		for _, gi := range ruleIdx {
			rs.ruleShard[gi] = shardPos
		}
	}
	if len(rs.shards) == 0 {
		return nil
	}
	return rs
}

// retain deletes from candidates every rule the Set rules out (its pattern cannot
// match data). Only shards holding at least one candidate are scanned — the
// keyword prefilter has usually narrowed candidates to a couple of shards, so the
// rest are never touched. Rules in a compile-skipped shard (ruleShard -1) are left
// untouched, so they are never wrongly pruned.
func (rs *regexSet) retain(data []byte, candidates map[int]struct{}) {
	if len(candidates) == 0 {
		return
	}
	// Bucket candidates by the shard that holds each.
	byShard := make(map[int][]int)
	for idx := range candidates {
		if idx >= 0 && idx < len(rs.ruleShard) {
			if shardPos := rs.ruleShard[idx]; shardPos >= 0 {
				byShard[shardPos] = append(byShard[shardPos], idx)
			}
		}
	}
	for shardPos, cands := range byShard {
		shard := rs.shards[shardPos]
		// Track only whether each candidate in this shard matched; the Set's other
		// hits (non-candidate rules) are irrelevant.
		hit := make(map[int]bool, len(cands))
		for _, idx := range cands {
			hit[idx] = false
		}
		for _, local := range shard.set.FindAll(data, -1) {
			g := shard.ruleIdx[local]
			if _, isCand := hit[g]; isCand {
				hit[g] = true
			}
		}
		for idx, matched := range hit {
			if !matched {
				delete(candidates, idx)
			}
		}
	}
}
