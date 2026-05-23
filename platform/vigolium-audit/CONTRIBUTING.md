# Contributing to vigolium-audit

Thanks for your interest in improving `vigolium-audit`! This guide covers local
setup, the project conventions, and what we look for in a pull request.

## Prerequisites

- [Bun](https://bun.sh) **>= 1.3.0** (`engines.bun` enforces this). Use `bun`
  rather than `node`/`npm`/`npx` throughout.
- To exercise a real audit you'll also need [`claude`](https://www.npmjs.com/package/@anthropic-ai/claude-code)
  and/or [`codex`](https://www.npmjs.com/package/@openai/codex) on `PATH`, plus
  the matching API key or ambient subscription auth. The test suite does **not**
  require either — unit and integration tests never spawn the CLIs or hit the
  network.

## Getting started

```bash
bun install
bun run dev -- run --mode lite --agent claude --target ./tests/fixtures/...   # run the CLI from source
```

## Common commands

```bash
bun test                                     # all tests (unit + integration)
bun test tests/unit/orchestrator.test.ts     # a single file
bun test --test-name-pattern "topological"   # a single test by name
bun run typecheck                            # tsc --noEmit (strict)
bun run lint                                 # tsc with --noUnusedLocals/--noUnusedParameters
bun run preflight                            # typecheck + lint + test + build, end to end
bun run build                                # current-platform binary
```

Run `bun run preflight` before opening a PR — it's exactly what CI runs (plus a
build), so a green preflight means a green CI.

## Project conventions

- **TypeScript is strict.** `tsconfig.json` enables `strict`,
  `noUncheckedIndexedAccess`, `noImplicitOverride`, and
  `exactOptionalPropertyTypes`. The last one means you cannot assign `undefined`
  to an optional field — use the `compact(...)` helper or a conditional spread
  (`...(x !== undefined ? { field: x } : {})`). There are many examples in
  `src/engine/orchestrator.ts` and `src/cli/run.ts`.
- **Imports use the `.js` extension** on TypeScript sources
  (`moduleResolution: bundler`), and `@/*` resolves to `src/*`.
- **No floating promises.** Fire-and-forget work must attach a `.catch(...)` so
  a rejected promise can't crash the process. If a result genuinely doesn't
  matter, `void somePromise.catch(() => {})` documents that intent.
- **Match the surrounding style.** Comments explain *why*, not *what*. Keep the
  comment density and naming consistent with the file you're editing.

## Editing methodology content

The audit methodology (agent prompts, mode workflows, skills) is **vendored
content** under `src/content/`, not code. If you change anything under
`src/content/agent-defs/` or `src/content/command-defs/`:

- Dev mode (`bun run dev` / `bun test`) picks it up immediately.
- Regenerate the SDK-safe variants before committing:

  ```bash
  bun run transform   # regenerates src/content/sdk-variants/
  ```

  CI does **not** do this for you, and the codex/SDK code path reads from
  `sdk-variants/`.

- The compiled binary inlines `src/content/` at build time, so shipping a
  content change requires a rebuild.

A mode is just a YAML phase graph in `src/content/command-defs/<mode>.md`
frontmatter — there are no hardcoded phase IDs in the engine. Any phase
referenced in `depends_on`/`parallel_with` must exist in `phases:`.

## Tests

- Add unit tests next to the module you change under `tests/unit/`.
- For end-to-end behavior, follow the `ScriptedFakeAdapter` pattern in
  `tests/integration/e2e-lite.test.ts` — it writes real files to a tmpdir and
  drives the orchestrator without mocking the SDK.
- Tests must not require network access or a real `claude`/`codex` binary.

## Pull requests

1. Branch off `main`.
2. Keep the change focused; large refactors are easier to review when split out
   from behavior changes.
3. Ensure `bun run preflight` passes.
4. Describe the motivation and any user-visible behavior change in the PR
   description, and add a `CHANGELOG.md` entry under **Unreleased**.

## Reporting security issues

Please do **not** file public issues for security vulnerabilities — see
[SECURITY.md](./SECURITY.md) for private reporting instructions.

## License

By contributing, you agree that your contributions will be licensed under the
[MIT License](./LICENSE).
