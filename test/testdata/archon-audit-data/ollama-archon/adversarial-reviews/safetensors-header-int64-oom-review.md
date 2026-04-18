Adversarial Review: safetensors-header-int64-oom
=================================================

Finding under review: archon/findings-draft/p8-024-safetensors-header-int64-oom.md

Step 1 - Restatement and sub-claims
-----------------------------------

Restatement: An attacker-supplied safetensors file tricks Ollama's conversion
code into attempting to allocate an absurdly large byte buffer. The allocation
either exhausts memory or panics the runtime. Because the conversion runs in a
goroutine that lacks a recover(), the server process terminates.

- Sub-claim A (input control): Any client that can upload a blob and issue
  POST /api/create with a Modelfile referring to a ".safetensors" file controls
  the exact bytes read as the safetensors header length.
- Sub-claim B (reach sink with no sanitization): The bytes reach
  parseSafetensors' int64 binary.Read, and the resulting n is passed directly
  into make([]byte, 0, n) without any range check.
- Sub-claim C (security effect): make([]byte, 0, n) with n near MaxInt64 or
  negative causes either an mmap failure / OOM kill or a makeslice panic; the
  enclosing goroutine has no recover, so the Ollama process dies.

All sub-claims are coherent.

Step 2 - Independent code path trace
------------------------------------

Source (attacker input) -> sink (vulnerable make):

1. server/routes.go:1703 r.POST("/api/create", s.CreateHandler)
   - Middleware chain: cors.New, allowedHostsMiddleware. No auth.
   - allowedHostsMiddleware only rejects non-loopback Host headers when server
     is bound to loopback. It is bypassed on LAN/public deployments.
2. server/create.go:46 CreateHandler binds the request and at line 99 spawns:
     go func() { defer close(ch); ... }()
   - No defer/recover() inside this goroutine.
3. create.go:175 calls convertModelFromFiles(r.Files, baseLayers, false, fn)
4. create.go:331 switches on detectModelTypeFromFiles(files). For ".safetensors"
   filenames it calls convertFromSafetensors(files, ...).
5. create.go:400 convertFromSafetensors creates a tmpDir, hardlinks the
   uploaded blobs under their declared names, then at line 441 calls
     convert.ConvertModel(os.DirFS(tmpDir), t)
6. convert/convert.go:374 ConvertModel -> parseTensors at line 381.
7. convert/reader.go:76 parseTensors matches "*.safetensors" (line 81) and
   calls parseSafetensors.
8. convert/reader_safetensors.go:25 parseSafetensors:
     var n int64
     binary.Read(f, LittleEndian, &n)              // line 35
     b := bytes.NewBuffer(make([]byte, 0, n))      // line 39  <-- SINK

Sanitization between source and sink: none. n is not range-checked, not capped
against file size, not compared to zero.

The safetensors specification declares the header length as a little-endian
uint64. Reading it as int64 means values with the high bit set decode as
negative integers, which trigger makeslice "cap out of range".

Step 3 - Protection surface search
----------------------------------

Layer: Language
- Go's maxAlloc check in runtime (approx 1 << 50 on darwin/arm64 I tested)
  turns extreme allocations into a recoverable panic "makeslice: cap out of
  range" rather than an unrecoverable OOM-kill. Panics are still fatal to any
  goroutine without a recover().

Layer: Framework
- gin.Recovery is installed via gin.Default() at routes.go:1674, but it only
  guards the http handler goroutine. The convert work happens in a goroutine
  spawned by CreateHandler (create.go:99) which has no recover(). Confirmed by
  live reproduction (Test 2) where the panic escaped to the test runner.

Layer: Middleware
- allowedHostsMiddleware: blocks only browser-origin attacks against loopback
  binds; does not stop same-network or authenticated LAN/public callers.
- No authentication on /api/create or /api/blobs in the open-source server.

Layer: Application
- fs.ValidPath gate on file map keys (create.go:69, 414) validates only the
  filename path, not the blob contents.
- No size cap on header length at any point between binary.Read and the make.

Layer: Documentation
- SECURITY.md / changelog not reviewed; no accepted-risk statement identified.

No layer blocks the claimed attack.

Step 4 - Real-environment reproduction
---------------------------------------

Environment: built at the current repo HEAD (57653b8e) on darwin/arm64, Go 1.26.1.

Attempt 1: Direct call to convertFromSafetensors with a blob whose first 8
bytes are 0x7FFFFFFFFFFFFFFF little-endian.
Result: panic "runtime error: makeslice: cap out of range" in
parseSafetensors at reader_safetensors.go:39. (Captured via defer in test;
see archon/real-env-evidence/safetensors-header-int64-oom/reproduction.txt.)

Attempt 2: Simulated CreateHandler goroutine. Launched convertFromSafetensors
inside a goroutine with no recover(), matching server/create.go:99 exactly.
Result: panic escaped the goroutine, crashed the test binary:
  panic: runtime error: makeslice: cap out of range
  goroutine 39 [running]:
  github.com/ollama/ollama/convert.parseSafetensors ... reader_safetensors.go:39
  github.com/ollama/ollama/convert.parseTensors ... reader.go:94
  github.com/ollama/ollama/convert.ConvertModel ... convert.go:381
  github.com/ollama/ollama/server.convertFromSafetensors ... create.go:441

Evidence stored at:
  /Users/bytedance/Desktop/demo/ollama/archon/real-env-evidence/safetensors-header-int64-oom/reproduction.txt
  /Users/bytedance/Desktop/demo/ollama/archon/real-env-evidence/safetensors-header-int64-oom/create_oom_handler_test.go.txt
  /Users/bytedance/Desktop/demo/ollama/archon/real-env-evidence/safetensors-header-int64-oom/create_oom_test.go.txt

Note on mechanism: the finding states the crash arises from mmap failure
(unrecoverable OOM). On this platform the crash instead arises from Go's
makeslice cap-out-of-range panic triggered by maxAlloc. Either way the
enclosing detached goroutine is unrecovered and kills the process.

Step 5 - Briefs
---------------

Prosecution brief:
- An unauthenticated (or merely same-network) attacker can upload an 8-byte
  blob via POST /api/blobs/:digest and then reference it as .safetensors via
  POST /api/create. The first 8 bytes feed directly into
  convert/reader_safetensors.go:35's binary.Read of int64 n with no range
  check, no file-size cap, no zero/negative check.
- Line 39 calls make([]byte, 0, n). With n = MaxInt64 the Go runtime panics
  with makeslice: cap out of range. With n negative (high bit set in the
  attacker bytes) the same panic fires. Confirmed via live reproduction at
  HEAD (Step 4).
- The conversion runs inside a goroutine spawned at create.go:99 that has no
  defer/recover(). gin.Recovery covers only the HTTP handler goroutine and
  cannot catch panics in detached goroutines. The panic therefore terminates
  the entire Ollama server process.
- Any defense based on the --experimental CLI flag applies only to
  x/create.CreateSafetensorsModel. The convert.ConvertModel path via
  /api/create is not gated by that flag.
- Impact: unauthenticated remote denial of service on any LAN-exposed Ollama
  instance. On default loopback binds, CSRF via a browser visiting a
  malicious page is blocked by allowedHostsMiddleware, but any local process
  or any LAN peer on OLLAMA_HOST=0.0.0.0 setups can trigger the crash.

Defense brief:
- Some controls narrow the blast radius:
  - Default bind is 127.0.0.1; allowedHostsMiddleware rejects cross-origin
    browser POSTs against loopback, so drive-by web attacks on a default-
    configured host are blocked.
  - Uploading the blob requires knowing the expected digest and matching it
    on upload (manifest.NewLayer verification).
- However, the defense cannot claim the primary attack is blocked:
  - No authentication is enforced, so any LAN-reachable Ollama (common in
    dev/enterprise setups) is exploitable.
  - The digest check on /api/blobs/:digest is easy to satisfy because the
    attacker chooses the content and computes its own SHA-256.
  - The panic in the detached goroutine is NOT caught by gin.Recovery;
    reproduction in Step 4 shows the process dies.
- The finding's specific mechanism description (mmap OOM-kill) is inaccurate
  on modern Go - the allocation fails as a panic via maxAlloc. The security
  effect (process crash) is identical, so this does not salvage a false
  positive verdict.

Step 6 - Severity challenge
---------------------------

Starting at MEDIUM:
- Remotely triggerable: YES on OLLAMA_HOST=0.0.0.0 deployments.
- Crosses meaningful trust boundary: YES (untrusted network -> process kill).
- Preconditions: minimal - only requires /api/blobs + /api/create reachable.
  Loopback-bound default limits the attack to local processes and browser
  attacks via allowedHostsMiddleware (blocked for loopback).
- Effect: single-request DoS of the Ollama service; no RCE, no data exfil,
  no integrity compromise.

Upgrade to HIGH: justified when the server is exposed beyond loopback, which
is the documented and common deployment pattern, though not the default.

Downgrade signals:
- Default bind is loopback, limiting drive-by exploitation to co-located
  attackers.
- Recovery is immediate once the service is restarted; no persistence.

Final severity: HIGH (matches the original) - remote unauthenticated
single-shot DoS against commonly-exposed configurations is a well-established
HIGH-severity class. Not CRITICAL because there is no auth bypass, RCE, or
data exfiltration, and default deployments require some network exposure
configuration change.

Step 7 - Verdict
----------------

CONFIRMED.

Decisive evidence: reproduction at HEAD (commit 57653b8e) shows a crafted
blob whose first 8 bytes are 0x7FFFFFFFFFFFFFFF causes parseSafetensors to
panic at convert/reader_safetensors.go:39 with "makeslice: cap out of range",
and that panic escapes the unrecovered goroutine at server/create.go:99,
crashing the host process. No framework or application control blocks the
chain between POST /api/create and the make() sink.

Note on finding accuracy: the finding's claimed mechanism
("runtime.mallocgc -> mmap -> unrecoverable OOM") is imprecise - the actual
mechanism is a maxAlloc panic in makeslice. Both paths terminate the process
because the enclosing goroutine is not recover()-guarded, so the verdict is
unchanged.

Severity-Final: HIGH
PoC-Status: executed
