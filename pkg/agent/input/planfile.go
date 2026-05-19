package input

import (
	"regexp"
	"strings"
)

// planRequestLinePattern matches a raw HTTP request start line anywhere in a
// multi-line plan file. Unlike httpMethodPattern (which is anchored to the
// start of a trimmed single input), this uses (?m) so ^ matches at every line
// boundary, and tolerates leading whitespace before the method.
var planRequestLinePattern = regexp.MustCompile(`(?m)^[ \t]*(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE|CONNECT)\s+\S+\s+HTTP/`)

// planFencePattern matches a fenced code block. The optional info string
// (```http / ```request / ``` / ```sh ...) is ignored for classification —
// a fence is treated as a request block only when its body contains a raw
// HTTP request line, so untagged fences holding a request still work.
var planFencePattern = regexp.MustCompile("(?s)```[^\n]*\n(.*?)\n?```")

// crlfReplacer normalizes Windows/old-Mac line endings to \n in a single
// pass. NewReplacer matches \r\n before bare \r, so it is order-correct.
var crlfReplacer = strings.NewReplacer("\r\n", "\n", "\r", "\n")

// ParsePlanFile splits a plan file into an instruction (free-text guidance)
// and zero or more raw HTTP request blocks (seed inputs).
//
// Format (no structured header — the file is what an operator would paste):
//
//   - Prose appearing before the first HTTP request becomes the instruction.
//   - Fenced ```http / ```request blocks (or any fenced block whose body is a
//     raw HTTP request) are each extracted as one request; everything outside
//     the fences is the instruction.
//   - When there are no usable fenced request blocks, the region from the
//     first request line to EOF is split on lines that are exactly "---" into
//     independent request blocks.
//   - A file with no request line at all is treated as instruction-only
//     (requests is nil); the caller must then supply --target.
//
// Parsing is lenient: a "---"-delimited block that does not contain a request
// line is folded back into the instruction rather than rejected. If no fenced
// block contains an HTTP request, the fenced path is abandoned and the
// auto-split path runs, so a stray ```bash fence above a real request does
// not suppress it.
func ParsePlanFile(raw string) (instruction string, requests []string) {
	raw = crlfReplacer.Replace(raw)

	// 1. Fenced-block path: take it only when at least one fence holds a
	//    request. Otherwise fall through to auto-split so a stray ```bash
	//    fence in the prose doesn't suppress request detection.
	if strings.Contains(raw, "```") {
		if instr, reqs, ok := parseFencedPlan(raw); ok {
			return instr, reqs
		}
	}

	// 2. Auto-split path.
	loc := planRequestLinePattern.FindStringIndex(raw)
	if loc == nil {
		// Instruction-only plan — no seed request present.
		return strings.TrimSpace(raw), nil
	}

	instruction = strings.TrimSpace(raw[:loc[0]])
	region := raw[loc[0]:]

	var extraInstruction []string
	for _, block := range splitOnRuleLines(region) {
		block = strings.TrimSpace(block)
		if block == "" {
			continue
		}
		if planRequestLinePattern.MatchString(block) {
			requests = append(requests, block)
		} else {
			extraInstruction = append(extraInstruction, block)
		}
	}

	if len(extraInstruction) > 0 {
		merged := strings.Join(extraInstruction, "\n\n")
		if instruction == "" {
			instruction = merged
		} else {
			instruction = instruction + "\n\n" + merged
		}
	}

	return instruction, requests
}

// parseFencedPlan extracts fenced code blocks whose body is a raw HTTP request
// as request seeds. ok is true only when at least one such fenced request was
// found; the caller falls back to auto-split otherwise. Text outside request
// fences (including non-request fences, kept verbatim) forms the instruction.
func parseFencedPlan(raw string) (instruction string, requests []string, ok bool) {
	matches := planFencePattern.FindAllStringSubmatchIndex(raw, -1)
	if len(matches) == 0 {
		return "", nil, false
	}

	var instrParts []string
	cursor := 0
	for _, m := range matches {
		fenceStart, fenceEnd := m[0], m[1]
		bodyStart, bodyEnd := m[2], m[3]
		body := raw[bodyStart:bodyEnd]

		instrParts = append(instrParts, raw[cursor:fenceStart])
		if planRequestLinePattern.MatchString(body) {
			requests = append(requests, strings.TrimSpace(body))
		} else {
			// Not a request — keep the fenced block verbatim as instruction.
			instrParts = append(instrParts, raw[fenceStart:fenceEnd])
		}
		cursor = fenceEnd
	}
	instrParts = append(instrParts, raw[cursor:])

	if len(requests) == 0 {
		return "", nil, false
	}
	return strings.TrimSpace(strings.Join(instrParts, "")), requests, true
}

// splitOnRuleLines splits text into blocks on lines that are exactly "---"
// (after trimming surrounding whitespace). The delimiter line itself is
// dropped. Used to separate multiple request blocks in the auto-split path.
func splitOnRuleLines(s string) []string {
	lines := strings.Split(s, "\n")
	var blocks []string
	var cur []string
	for _, ln := range lines {
		if strings.TrimSpace(ln) == "---" {
			blocks = append(blocks, strings.Join(cur, "\n"))
			cur = nil
			continue
		}
		cur = append(cur, ln)
	}
	blocks = append(blocks, strings.Join(cur, "\n"))
	return blocks
}
