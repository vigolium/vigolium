# 1ed2881e — Template nil-pipe crash (templates: fix crash in improperly defined templates)

- **Type**: undisclosed-fix
- **Cluster ID**: template-parse-dos
- **Files**: `template/template.go`, `server/images.go`
- **Author / date**: patrick@infrahq.com / 2025-10-02

## Patch summary

Pre-patch, `Identifiers(parse.Node)` and `Vars()` returned `[]string` and
crashed with a nil-pointer deref when they encountered a `*parse.TemplateNode`
/ `*parse.ActionNode` / `*parse.BranchNode` whose `.Pipe` was nil — for example
`{{template "foo"}}` (a template invocation with no pipeline) parses
successfully but produces a `TemplateNode{Pipe: nil}`. Callers like
`(*Template).Parse` (line 148) and `Capabilities()` (server/images.go:108)
would then dereference `n.Pipe.Cmds` and panic.

The patch:

1. `Identifiers` now returns `([]string, error)` and explicitly errors with
   `"undefined template specified" / "undefined action in template" /
   "undefined branch"` when it sees a nil `Pipe` on `TemplateNode`,
   `ActionNode`, or `BranchNode`.
2. `Vars()` propagates that error.
3. `template.Parse` calls `Vars()` and returns the error, so a malformed
   `{{template "foo"}}` Modelfile fragment is now rejected at model-load
   time instead of crashing later.
4. `server/images.go::Capabilities()` now logs `slog.Warn` instead of
   panicking when `Vars()` errs.
5. `Execute()` now also calls `Vars()` first and propagates errors.

## Bypass verdict

`bypassable` — the specific nil-pointer crash that the patch targets is
properly closed for the `TemplateNode/ActionNode/BranchNode` case, but
**other DoS / panic vectors against the same Modelfile-template attack
surface remain unfixed**.

## Evidence

### B1. Memory exhaustion via deeply nested templates (DoS, not patched)

Verified empirically against Go 1.26.1's `text/template`:

- `{{if .X}}` repeated 200 000× nested still parses without error.
- Each level allocates an `IfNode + ListNode + PipeNode + CommandNode +
  FieldNode`, so a template of N levels uses O(N) AST objects.
- There is no size limit anywhere on the `application/vnd.ollama.image.template`
  blob in `server/images.go:351-361` — `os.ReadFile` reads the entire blob
  into memory, then `template.Parse(string(bts))` parses it.

A malicious Modelfile (or a malicious published model that the server pulls)
containing a multi-megabyte / multi-gigabyte template can be served from the
registry and will exhaust the host's RAM at parse time. `Vars()`/`Identifiers()`
recurse through the tree without an O(depth) early-out, multiplying the
allocation. Because the parse happens during `Capabilities()` evaluation
(which is invoked from `/api/show` and several other request paths), an
unauthenticated request can trigger the OOM repeatedly.

The patch does nothing to limit input size or recursion depth.

### B2. Stack overflow on deeply nested templates from non-default-stack callers

`runtime: stack overflow` is a `runtime.throw` (not a Go panic, not
recoverable). Goroutines auto-grow up to ~1 GB of stack, so the typical HTTP
handler is safe, but call paths that share the main goroutine or call the
template package from pinned C threads / signal handlers would crash the
whole process. Reproduced locally on the main goroutine at ~50k-deep
`{{if .X}}…{{end}}`. Out of scope of the patch.

### B3. Same-class nil deref in `tools/template.go`

`tools.findToolCallNode` (`tools/template.go:50-103`) walks the parsed
template AST looking for `IfNode` whose pipeline references `.ToolCalls`. It
dereferences `n.Pipe.Cmds` (line 52) without a nil-check, and recurses with
`findToolCallNode(n.List.Nodes)` for `IfNode`, `RangeNode`, `WithNode`
without nil-checking `.List`. `findTextNode` (line 108-156) has the same
pattern.

`tools.NewParser(m.Template.Template, req.Tools)` is invoked from the chat
handler at `server/routes.go:2382` whenever `req.Tools` is non-empty and
`builtinParser` is nil. Empirically Go's `text/template` parser always
populates `IfNode.List` (it is `&ListNode{Nodes: nil}` for an empty body),
so the in-tree-from-parser path is currently safe — but this is *coupling
an Ollama invariant to an undocumented stdlib invariant*. The patch under
review introduced more guards in `template.Identifiers` for exactly this
class of bug; the analogous walker in `tools/` did not get the same
treatment.

The repo also constructs templates with a hand-built tree in
`template.(*Template).Subtree` (`template/template.go:244-251`) and
`thinking.InferTags` operates on `t.Root` directly — neither validates
that the produced sub-tree has well-formed pipes before handing it back to
callers like `tools.NewParser`.

### B4. `tools.findToolCallNode` ignores `*parse.TemplateNode`

`findToolCallNode` only recurses into `IfNode / ListNode / RangeNode /
WithNode`. A model template that hides its tool-call branch inside a
`{{template "tools" .}}` invocation (a feature templates legitimately use)
will be silently skipped, so the inferred tool-call tag will fall back to
`"{"` and tool parsing semantics change. Not a panic, but a behavior gap
in the same hardening exercise.

### B5. `Vars()` returns *partial* identifier list on error

```go
for _, tt := range t.Templates() {
    for _, n := range tt.Root.Nodes {
        v, err := Identifiers(n)
        if err != nil {
            return vars, err   // <-- returns un-deduped, un-sorted partial vars
        }
        vars = append(vars, v...)
    }
}
```

In `Capabilities()`:

```go
v, err := m.Template.Vars()
if err != nil {
    slog.Warn("model template contains errors", "error", err)
}
if slices.Contains(v, "tools") || ...
```

The handler does **not** return on error; it consumes the partial slice. A
malformed template that contains the literal identifier `tools` *before* the
nil-pipe construct (`{{ .tools }} {{template "x"}}`) would be flagged as
having `CapabilityTools` even though the rest of the template is unparseable.
This isn't directly a crash, but it's a downstream-correctness regression
introduced by the silent-warn pattern.

In practice the load path in `server/images.go:358` rejects malformed
templates outright (because `template.Parse` now propagates the error), so
`m.Template` would be nil and `Capabilities()` returns early. But any
future caller that constructs a `Template` without going through `Parse`
(see B6) will hit this gap.

### B6. Bypass of the new validation by skipping `template.Parse`

The new validation lives in `template.Parse` only. Three callsites in the
tree construct/use templates without going through it:

- `template/template.go:94`: `var DefaultTemplate, _ = Parse("{{ .Prompt }}")`
  — safe (constant).
- `template/template.go:337`: `template.Must(template.New("").AddParseTree("",
  &tree)).Execute(...)` — internal, fed from `deleteNode(t.Template.Root.Copy(), …)`.
  The tree comes from the already-validated `m.Template`, so transitively
  safe.
- `tools/tools_test.go`, `thinking/template_test.go`, `tools/template_test.go`
  — test code uses raw `text/template.New("").Parse(...)` and bypasses the
  ollama wrapper entirely. Not exploitable in production.

So in the current tree all production callers go through the patched
`Parse`. This is a fragile invariant: any new feature that imports
`text/template` directly (rather than `ollama/template`) re-opens the
crash surface.

### B7. `Identifiers` is missing `parse.TemplateNode` Pipe-nil check on inner templates referenced by `define`

`{{define "x"}}{{template "y"}}{{end}}{{template "x"}}` parses successfully
and produces both an outer `TemplateNode("x", Pipe=<nil>)` and an inner
`TemplateNode("y", Pipe=<nil>)` inside the named template `"x"`. `Vars()`
iterates `t.Templates()` so it visits every named tree and now detects both
nil-pipe nodes. This case is correctly fixed.

### B8. Template that compiles but panics at *execute* time

Stdlib `text/template.Execute` runs under `errRecover`, which converts
walk-time panics into typed errors. Verified that
`{{template "missing"}}` parses successfully and yields
`template "missing" not defined` as a returned error rather than a panic.
So execute-time crashes are gated by stdlib's recover and not a viable
bypass.

## Files / lines of interest

- `/Users/bytedance/Desktop/demo/ollama/template/template.go:145-165`
  (Parse — adds Vars() validation)
- `/Users/bytedance/Desktop/demo/ollama/template/template.go:171-189`
  (Vars now returns error)
- `/Users/bytedance/Desktop/demo/ollama/template/template.go:511-577`
  (Identifiers nil-pipe guards)
- `/Users/bytedance/Desktop/demo/ollama/server/images.go:125-142`
  (Capabilities still proceeds on Vars() error)
- `/Users/bytedance/Desktop/demo/ollama/server/images.go:351-361`
  (template blob loaded with no size limit)
- `/Users/bytedance/Desktop/demo/ollama/tools/template.go:50-103`
  (findToolCallNode — same class of walker, no nil-Pipe / nil-List guard)
- `/Users/bytedance/Desktop/demo/ollama/tools/template.go:108-156`
  (findTextNode — same)
- `/Users/bytedance/Desktop/demo/ollama/server/create.go:728-733`
  (setTemplate parses twice — both protected by patch)
- `/Users/bytedance/Desktop/demo/ollama/server/routes.go:444`
  (request-supplied template — protected)
- `/Users/bytedance/Desktop/demo/ollama/thinking/template.go:9-55`
  (templateVisit — already nil-guards at top, safe)

## Suggested follow-ups for the parent agent

1. Add a max-size and/or max-depth check on the template blob in
   `server/images.go::Capabilities` and `template.Parse`. Currently a
   pulled model can ship an arbitrarily large `application/vnd.ollama.image.template`
   layer that is mmap-loaded and recursively walked.
2. Apply the same nil-Pipe / nil-List guards to `tools/template.go`'s
   `findToolCallNode` and `findTextNode` so they don't depend on the
   undocumented invariant that stdlib `text/template` always allocates an
   empty `ListNode` for `if/range/with` bodies.
3. Make `Capabilities()` short-circuit on `Vars() error` instead of
   logging-and-continuing with a partial identifier list.
4. Audit other helpers (`Subtree`, `deleteNode`, `InferTags`,
   `rangeUsesField`) for type-assertion-of-nil-interface panics that mirror
   the `t.Pipe = n.(*parse.PipeNode)` pattern in `deleteNode`.
