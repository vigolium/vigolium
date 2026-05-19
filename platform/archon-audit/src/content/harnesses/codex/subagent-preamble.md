> **CRITICAL — Output Chunking (Codex sub-agent profile)**
> Keep each file write under 3 KB. Write each ### section as a separate append
> (`cat >> file` or equivalent). Never accumulate full output before writing.
> Split large tables across multiple writes.
