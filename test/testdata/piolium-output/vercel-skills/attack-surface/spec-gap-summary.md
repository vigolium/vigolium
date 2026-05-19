# Stage 07 — Specification & Parser Gaps

## Specs reviewed

- RFC 8615 Well-Known URIs and Security Considerations.
- RFC 3986 URI Generic Syntax and Security Considerations.
- Agent Skills specification (`https://agentskills.io/specification.md`) and reference validator.
- Agent Skills client implementation guide (`https://agentskills.io/client-implementation/adding-skills-support.md`).
- Git ref/branch rules (`git check-ref-format`) and git clone semantics.
- Claude plugin manifest handling and npm provenance/release expectations were reviewed for medium+ exploit paths; no distinct spec-gap finding was filed beyond existing P4/P6 coverage.

## Findings filed

1. `piolium/findings-draft/p7-001-rfc8615-path-relative-well-known-shadowing.md` — RFC 8615 root-only `.well-known` semantics are violated by path-relative discovery that is tried before the origin root.
2. `piolium/findings-draft/p7-002-agent-skill-name-constraints-not-enforced.md` — Agent Skills `name` constraints and parent-directory equality are not enforced before deriving install directories.

## Notes

- HTTP well-known transport, missing fetch/parser limits, direct git/ref validation, duplicate names, blob snapshot trust, lockfile update trust, and `node_modules` sync were already covered by Phase 4 findings and were not duplicated here.
- The public Agent Skills site exposes a `.well-known/agent-skills` index with a newer `url`/`digest` shape, but the authoritative discovery schema host was not resolvable from this runtime; no separate digest-verification finding was filed without a stable normative clause.
