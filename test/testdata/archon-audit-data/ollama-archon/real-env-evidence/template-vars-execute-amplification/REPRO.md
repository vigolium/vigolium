Environment: go 1.26.1 darwin/arm64, ollama @ 57653b8e (main)

Executed tests (copied into template/ to bypass module boundaries, then removed):

1. TestLargeTemplate
   - 52MB template parsed in ~2.07s (no size limit)
   - Vars() x10 on that 52MB template = 3.48s (avg ~348ms per call)

2. TestVarsCostOnLargeTemplate
   - 10MB template (realistic) parsed in ~?s
   - Vars() x10 = 667ms (avg ~67ms per call)
   - Every /api/chat render pays this 67ms VArs() cost (plus ~300ms Parse from GetModel fresh load)

3. TestAmplificationRatio
   - Nested {{range .Messages}}{{range .ToolCalls}} template
   - At msgs=100 tc=50 keys=50: input 12.4MB, render 1.5ms -> only 0.12 us/KB
   - At msgs=500 tc=100 keys=100: input 247MB, render 2.6ms -> only 0.01 us/KB
   - Amplification ratio is actually poor: server renders faster than attacker can feed data.
   - Template execution time is dominated by memory copy of output, not CPU.

Conclusion: the *real* DoS primitive is #1 and #2 - uncapped Parse/Vars on a stored
large template, not the "nested range" amplification claim. A 100MB stored template
would make every /api/chat take ~3s+ of pure CPU.
