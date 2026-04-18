Phase: 8
Sequence: 033
Slug: wordpiece-rune-amplification
Verdict: VALID
Rationale: tokenizer/wordpiece.go:61 pre-allocates make([]rune, 0, len(s)*3) where each rune is int32 (4 bytes); a 500MB input produces a 6GB capacity allocation. The multiplication cannot overflow int on 64-bit, but the 12× (3 runes × 4 bytes) amplification is a real DoS vector when /api/tokenize or /api/generate body size is not capped.
Severity-Original: MEDIUM
PoC-Status: pending
Pre-FP-Flag: none
Debate: archon/chamber-workspace/chamber-02/debate.md

## Summary

`tokenizer/wordpiece.go:59-76` pre-allocates a rune slice with capacity `len(s)*3` to accommodate worst-case CJK-character padding. Since `rune` is `int32` (4 bytes), the memory cost is 12 bytes per input byte (3 runes × 4 bytes). The SAST flag (`codeql-go/allocation-size-overflow-tokenizer/wordpiece.go-61`) is a false positive for overflow (requires `len(s) > MaxInt/3`, impossible) but the underlying amplification IS a real memory-pressure vector.

## Location

`tokenizer/wordpiece.go:61`

## Attacker Control

Any caller with a large-body POST. Reached via `/api/tokenize`, `/api/generate`, `/api/chat` when the model uses WordPiece tokenization (BERT-family). No explicit MaxBytesReader cap on those routes' body size in the current tree.

## Trust Boundary Crossed

Network API -> process heap.

## Impact

12× RAM amplification of attacker input. 500MB POST -> 6GB transient allocation inside the tokenizer. Sustained low-RPS attacks can exhaust process memory without ever triggering an explicit OOM check.

## Evidence

```
// tokenizer/wordpiece.go:59-76
func (wpm WordPiece) words(s string) iter.Seq[string] {
    return func(yield func(string) bool) {
        runes := make([]rune, 0, len(s)*3)   // <-- 12x amplification
        for _, r := range s {
            switch {
            case r >= 0x4E00 && r <= 0x9FFF, ... :
                runes = append(runes, ' ', r, ' ')
            default:
                runes = append(runes, r)
            }
        }
        ...
```

Advocate (Round 3) correctly noted the overflow is impossible on 64-bit; Synthesizer overrides the "SAST false positive" recommendation because the amplification IS real and is a MEDIUM DoS vector.

## Reproduction Steps

1. Deploy Ollama with a BERT-family embedding model (WordPiece tokenization).
2. `POST /api/embeddings` with a 100MB prompt body.
3. Observe RSS spike to ~1.2GB during the tokenizer pass.

Fix direction:
- Change the initial capacity to `len(s)` (append-grown as needed) or a small constant.
- Add explicit request-body cap via `http.MaxBytesReader` on tokenize/generate/chat routes.
