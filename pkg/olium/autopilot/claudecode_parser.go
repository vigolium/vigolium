package autopilot

import (
	"encoding/json"
	"strings"
)

// claudeCodeBlockParser scans the streaming text of the claude-code provider
// for protocol blocks the model emits in lieu of engine tool calls. The
// claude-code provider runs Claude Code's CLI as a black-box LLM (its native
// Bash/Read/WebFetch tools execute internally, never reaching the olium
// engine), so report_finding / halt_scan can't be wired as real tool calls.
// Instead, the autopilot prompt instructs the model to emit sentinel blocks
// inline in its text output, which this parser extracts and dispatches.
//
// Two block kinds are recognized:
//
//	<<<VIG:FINDING>>>{...JSON matching the report_finding schema...}<<<VIG:END>>>
//	<<<VIG:HALT>>>short halt reason<<<VIG:END>>>
//
// Recognized blocks are consumed (not echoed to the operator). Anything
// else passes through unchanged. Blocks split across deltas are buffered.
//
// Feed/Flush are not goroutine-safe — call from a single reader.
type claudeCodeBlockParser struct {
	buf       strings.Builder
	onFinding func(args map[string]any)
	onHalt    func(reason string)
}

const (
	sentinelStart = "<<<VIG:"
	sentinelEnd   = "<<<VIG:END>>>"
	tagSeparator  = ">>>"
)

// Feed appends s to the buffer and returns the portion that is safe to
// write to stdout. Complete sentinel blocks in the buffer are consumed
// and dispatched via the callbacks. Anything that could still be the
// prefix of a sentinel is held back for the next call.
func (p *claudeCodeBlockParser) Feed(s string) string {
	if s != "" {
		p.buf.WriteString(s)
	}

	var emit strings.Builder
	for {
		buf := p.buf.String()
		i := strings.Index(buf, sentinelStart)
		if i < 0 {
			// No sentinel opener found. Hold back the longest suffix that
			// is a prefix of sentinelStart, in case the next delta
			// completes a split sentinel.
			hold := suffixPrefixOverlap(buf, sentinelStart)
			emit.WriteString(buf[:len(buf)-hold])
			p.buf.Reset()
			p.buf.WriteString(buf[len(buf)-hold:])
			break
		}
		// Emit everything before the opener as-is.
		emit.WriteString(buf[:i])
		buf = buf[i:]

		// Look for the end marker after the opener prefix. Searching from
		// len(sentinelStart) onward prevents an opener like "<<<VIG:FINDING>>>"
		// from being matched as its own end.
		rel := strings.Index(buf[len(sentinelStart):], sentinelEnd)
		if rel < 0 {
			// Opener present but no end yet — hold and wait for more.
			p.buf.Reset()
			p.buf.WriteString(buf)
			break
		}
		end := rel + len(sentinelStart)
		consumeTo := end + len(sentinelEnd)

		// block = "<TAG>>>payload" (without surrounding <<<VIG: and <<<VIG:END>>>).
		block := buf[len(sentinelStart):end]
		tagEnd := strings.Index(block, tagSeparator)
		if tagEnd < 0 {
			// Malformed opener (no ">>>" after tag). Skip the whole block
			// silently to avoid leaking protocol noise to the operator.
			p.buf.Reset()
			p.buf.WriteString(buf[consumeTo:])
			continue
		}
		tag := block[:tagEnd]
		payload := block[tagEnd+len(tagSeparator):]
		switch tag {
		case "FINDING":
			p.dispatchFinding(payload)
		case "HALT":
			p.dispatchHalt(payload)
		default:
			// Unknown tag — pass through verbatim so prompt drift is
			// visible rather than silently swallowed.
			emit.WriteString(buf[:consumeTo])
		}

		p.buf.Reset()
		p.buf.WriteString(buf[consumeTo:])
	}
	return emit.String()
}

// Flush returns whatever is left in the buffer. Called once at end of run
// so the operator isn't left missing a partial-sentinel tail.
func (p *claudeCodeBlockParser) Flush() string {
	out := p.buf.String()
	p.buf.Reset()
	return out
}

func (p *claudeCodeBlockParser) dispatchFinding(rawJSON string) {
	if p.onFinding == nil {
		return
	}
	var args map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(rawJSON)), &args); err != nil {
		return
	}
	p.onFinding(args)
}

func (p *claudeCodeBlockParser) dispatchHalt(reason string) {
	if p.onHalt == nil {
		return
	}
	p.onHalt(strings.TrimSpace(reason))
}

// suffixPrefixOverlap returns the length of the longest suffix of s that is
// also a prefix of prefix. Used to decide how many trailing bytes of the
// buffer might be the start of a split sentinel.
func suffixPrefixOverlap(s, prefix string) int {
	max := len(prefix) - 1
	if len(s) < max {
		max = len(s)
	}
	for k := max; k > 0; k-- {
		if strings.HasSuffix(s, prefix[:k]) {
			return k
		}
	}
	return 0
}
