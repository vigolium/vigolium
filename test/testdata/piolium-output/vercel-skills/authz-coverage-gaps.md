# Authorization Coverage Gaps

Stage P5 found no inbound web/RPC/queue/scheduler route framework in this repository. Authz coverage is therefore centered on CLI operations, outbound fetch/git operations, and GitHub Actions event handlers.

## Gaps / manual-review notes

1. **GitHub repository controls are external to source.** Publish authorization for `.github/workflows/publish.yml` depends on branch protection, allowed workflow dispatch actors, environment/secret policies, and npm token scoping. The workflow source gates on `push`/`workflow_dispatch`, but P5 cannot verify repository settings.
2. **Distributed bundle parity not verified.** `dist/cli.mjs` was not present in the source tree scanned by P5; the matrix uses `src/**/*.ts` and `bin/cli.mjs` line evidence.
3. **No dynamic web route table exists.** Grep detectors for Express/Nest/GraphQL/proto/gRPC and Python/Go web frameworks returned no inbound handlers. The provider registry is present but only the well-known provider is statically exported/used; no plugin-loaded request handlers were observed.
4. **Application roles/tenants are not modeled because none exist.** Mutating operations are authorized by local OS permissions, explicit CLI flags/prompts, remote git/GitHub permissions, and GitHub Actions repository roles rather than app-layer RBAC.

## Endpoints requiring Phase 8 attention

No endpoint was assigned `Expected Scope = unknown` in the P5 matrix. If Phase 8 reviews CI/release access control, focus on repository settings for protected branches/tags, workflow dispatch permissions, npm token scope, and secret exposure policy.
