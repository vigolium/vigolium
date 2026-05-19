# V5 Existing Test Search Summary

Framework selected from env-strategies.json: `vitest` (`pnpm exec vitest`). Existing tests were searched with grep for affected functions/modules (`parseSource`, `cloneRepo`, `installSkillForAgent`, `copyDirectory`, `discoverSkills`, `parseSkillMd`, `runInstallFromLock`, `runSync`, `removeCommand`, `sanitizeName`).

Findings:

- `src/source-parser.test.ts` and `tests/source-parser.test.ts` exercise normal git/source parsing, but do not run a direct `ext::` source through `git clone`; they would not catch p10-001.
- `tests/installer-copy.test.ts` and `tests/installer-symlink.test.ts` exercise normal install copy/symlink behavior, but not an untrusted source symlink to an out-of-tree file or a project `.agents` symlink escaping the checkout; they would not catch p10-002 or p10-009.
- `tests/full-depth-discovery.test.ts` and `tests/plugin-manifest-discovery.test.ts` cover benign deduplication, but not attacker-before-curated duplicate names; they would not catch p10-005.
- `tests/sanitize-name.test.ts` documents lossy normalization of traversal-like names, but does not assert fail-closed Agent Skill name validation or trusted-skill overwrite behavior; it would not catch p10-008.
- `src/add.test.ts` only checks the empty-lock `experimental_install` path; it does not test a node_modules lock restore with unlisted dependency skills; it would not catch p10-010.
- `tests/sync.test.ts` covers node_modules discovery, lock writing, and multiple skills, but not duplicate `name` collisions across packages overwriting the same destination; it would not catch p12-node-modules-sync-duplicate-name-overwrite.
- `src/remove.test.ts` and `tests/remove-canonical.test.ts` cover normal removal and canonical-use protection, but not deletion through a symlinked project `.agents` base; they would not catch p12-project-scope-remove-symlinked-agent-base-escape.
- `tests/skill-matching.test.ts` covers non-string frontmatter values, but no oversized frontmatter/OOM case; it would not catch p12-unbounded-git-local-frontmatter-parse.

Generated reproducer tests were therefore added under each targeted finding directory and run individually with `--testTimeout=60000` plus an outer `timeout 90`.
