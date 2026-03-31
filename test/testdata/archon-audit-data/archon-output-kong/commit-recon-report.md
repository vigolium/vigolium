# Commit Archaeology Report

**Repository**: Kong/kong
**Commit range**: 2023-03-30..<HEAD 58f2daa56b90615f78d5953229936192cd1128e9>
**Branches searched**: origin/FTI-4283-KM-1008-admin-gui-csp-header-value, origin/FTI-6378, origin/HEAD -> origin/master, origin/KAG-6135, origin/RSLMsizepatch, origin/aigw-393, origin/backport-12515-to-master, origin/backport-13946-to-release/3.9.x, origin/backport-13995-to-release/3.9.x, origin/backport-14639-to-release/3.9.x, origin/chore/bazel-envrc-template, origin/chore/bump-resty-session-4.1.0, origin/chore/cache-stores, origin/chore/changelog-reviews-ai, origin/chore/kong-admin-v3.7.0.0, origin/chore/luajit-fix-sigment-release, origin/chore/rename-ngx-wasmx-module, origin/chore/side-by-side-pr-diffs--base, origin/chore/side-by-side-pr-diffs--less-diffs, origin/chore/side-by-side-pr-diffs--more-diffs
**Languages detected**: py, rs, go, js
**Project security vocabulary discovered**: PROJECT_VOCAB_VALIDATORS: (none), PROJECT_VOCAB_AUTH: (none), PROJECT_VOCAB_CONFIG: (none)
**Scan date**: 2026-03-30T06:34:32Z
**Total commits in repo**: 11254

## Summary Statistics

| Category | Commits Found | HIGH | MEDIUM | LOW |
|----------|--------------|------|--------|-----|
| 1. Dangerous Pattern Introduction | 0 | 0 | 0 | 0 |
| 2. Security Control Weakening | 0 | 0 | 0 | 0 |
| 3. Silent Security Fixes | 2 | 2 | 0 | 0 |
| 4. Reverted Security Fixes | 1 | 0 | 1 | 0 |
| 5. Secret Archaeology | 0 | 0 | 0 | 0 |
| 6. CI/CD Pipeline Weakening | 0 | 0 | 0 | 0 |
| 7. Suspicious Patterns | 0 | 0 | 0 | 0 |
| **Total (deduplicated)** | **3** | **2** | **1** | **0** |

## Priority Commits (top 30, ordered by risk)

| # | SHA | Category | Risk | Confidence | Author | Date | Description | Recommended Phase |
|---|-----|----------|------|-----------|--------|------|-------------|-------------------|
| 1 | 8958dd7749d86e6bb40c0765ddf978c194490c5c | Silent Security Fixes | HIGH | HIGH | Qi <add_sp@outlook.com> | 2024-08-21 | json-threat-protection rejects non-UTF8 and tightens length counting | Phase 2 (undisclosed-fix), Phase 5 |
| 2 | 99ca0b3a619ecae660f589d5ec6b379a04d117c3 | Silent Security Fixes | HIGH | HIGH | Niklaus Schen <8458369+Water-Melon@users.noreply.github.com> | 2024-09-20 | json-threat-protection fixes constraint defaults to avoid unsafe behavior | Phase 2 (undisclosed-fix), Phase 5 |
| 3 | 78816c26f383b2dac9b4d77498bb24d408237bca | Reverted Security Fixes | MEDIUM | — | Vinicius Mignot <vinicius.mignot@gmail.com> | 2024-08-28 | revert tls-metadata-headers intermediate cert metadata fix | Phase 2 |

## Category 3: Silent Security Fixes

### [8958dd77] json-threat-protection rejects non-UTF8 and tightens length counting
- **Commit**: `8958dd7749d86e6bb40c0765ddf978c194490c5c`
- **Author**: Qi <add_sp@outlook.com>
- **Date**: 2024-08-21T06:48:45Z
- **Files**: distribution/lua-resty-json-threat-protection; kong/plugins/json-threat-protection/handler.lua; spec-ee/03-plugins/45-json-threat-protection/03-integration_spec.lua
- **Pattern**: Adds stricter input validation (reject non-UTF8, correct length counting) in JSON threat protection.
- **Discovery source**: generic baseline
- **Risk**: HIGH
- **Confidence**: HIGH
- **FP assessment**: Changes add concrete validation in a security plugin without corresponding security-tagged commit message.
- **Downstream**: Phase 2 (undisclosed-fix), Phase 5 (deep-probe)

### [99ca0b3a] json-threat-protection fixes constraint default handling
- **Commit**: `99ca0b3a619ecae660f589d5ec6b379a04d117c3`
- **Author**: Niklaus Schen <8458369+Water-Melon@users.noreply.github.com>
- **Date**: 2024-09-20T10:04:29+08:00
- **Files**: changelog/unreleased/kong-ee/fix_container_depth_check_failure.yml; distribution/lua-resty-json-threat-protection; kong/plugins/json-threat-protection/handler.lua; spec-ee/03-plugins/45-json-threat-protection/02-api_spec.lua; spec-ee/03-plugins/45-json-threat-protection/03-integration_spec.lua
- **Pattern**: Fixes unsafe default constraint handling (negative value interpreted unexpectedly), affecting request acceptance.
- **Discovery source**: generic baseline
- **Risk**: HIGH
- **Confidence**: HIGH
- **FP assessment**: Protective logic added in threat-protection plugin; commit message lacks security keywords but touches security-critical path.
- **Downstream**: Phase 2 (undisclosed-fix), Phase 5 (deep-probe)

## Category 4: Reverted Security Fixes

### [78816c26] revert tls-metadata-headers intermediate certificates metadata
- **Commit**: `78816c26f383b2dac9b4d77498bb24d408237bca`
- **Author**: Vinicius Mignot <vinicius.mignot@gmail.com>
- **Date**: 2024-08-28T02:47:00-03:00
- **Files**: kong/plugins/tls-metadata-headers/handler.lua; kong/plugins/tls-metadata-headers/schema.lua; kong/clustering/compat/removed_fields.lua; spec/03-plugins/38-tls-metadata-headers/01-access_spec.lua; spec/03-plugins/38-tls-metadata-headers/02-integration_spec.lua; spec/fixtures/tls-metadata-headers/*
- **Pattern**: Reverts prior fix that added intermediate certificate metadata to X-Forwarded-Client-Cert header.
- **Discovery source**: generic baseline
- **Risk**: MEDIUM
- **FP assessment**: Direct revert of a fix commit (`fix(tls-metadata-headers)`) with functional changes in security-related plugin path.
- **Downstream**: Phase 2

## Category 1: Dangerous Pattern Introduction

No qualifying commits found (last 3 years).

## Category 2: Security Control Weakening

No qualifying commits found (last 3 years).

## Category 5: Secret Archaeology

No qualifying commits found (last 3 years).

## Category 6: CI/CD Pipeline Weakening

No qualifying commits found (last 3 years).

## Category 7: Suspicious Patterns

No qualifying commits found (last 3 years).
