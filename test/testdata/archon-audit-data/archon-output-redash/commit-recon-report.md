# Commit Archaeology Report

**Repository**: getredash/redash
**Commit range**: all history..<HEAD>
**Branches searched**: origin/master
**Languages detected**: py, js, ts
**Project security vocabulary discovered**:

- PROJECT_VOCAB_VALIDATORS: check_csrf, enforce_hard_limit, validate_result, verify_password, validate_data_source_type, check_settings, verify_jwt_token, verify_link_for_user, validate_token, verify_profile, filter_none, filter_by_tags
- PROJECT_VOCAB_AUTH: AccessPermission, PermissionsCheckMixin, ObjectPermissionsListResource, CheckPermissionResource, DefaultPolicy, setPolicy, updateSession, Auth, currentUser, login_required
- PROJECT_VOCAB_CONFIG: csrf, csp_allows_embeding, Content-Security-Policy, Strict-Transport-Security, X-Frame-Options, rate limit, throttle, allowlist, denylist, secure headers
  **Scan date**: 2026-03-29T16:50:15Z
  **Total commits in repo**: 1

## Summary Statistics

| Category                          | Commits Found | HIGH | MEDIUM | LOW |
| --------------------------------- | ------------- | ---- | ------ | --- |
| 1. Dangerous Pattern Introduction | 0             | 0    | 0      | 0   |
| 2. Security Control Weakening     | 0             | 0    | 0      | 0   |
| 3. Silent Security Fixes          | 0             | 0    | 0      | 0   |
| 4. Reverted Security Fixes        | 0             | 0    | 0      | 0   |
| 5. Secret Archaeology             | 0             | 0    | 0      | 0   |
| 6. CI/CD Pipeline Weakening       | 0             | 0    | 0      | 0   |
| 7. Suspicious Patterns            | 0             | 0    | 0      | 0   |
| Total (deduplicated)              | 0             | 0    | 0      | 0   |

## Priority Commits (top 30, ordered by risk)

| #   | SHA | Category | Risk | Confidence | Author | Date | Description | Recommended Phase |
| --- | --- | -------- | ---- | ---------- | ------ | ---- | ----------- | ----------------- |

No HIGH-risk commits identified in Categories 1-3 for this repository history.

## Category 1: Dangerous Pattern Introduction

No qualifying commits found. The only commit in history is a repository bootstrap; matched patterns occur primarily in tests/CI scaffolding or configuration defaults and do not qualify as HIGH-risk introductions in production code.

## Category 2: Security Control Weakening

No qualifying commits found. No evidence of guard/header/sanitizer removal in non-test paths.

## Category 3: Silent Security Fixes

No qualifying commits found. No protective-code additions with vague commit messages in security-critical paths.

## Category 4: Reverted Security Fixes

No revert commits found.

## Category 5: Secret Archaeology

No qualifying commits found.

## Category 6: CI/CD Pipeline Weakening

No qualifying commits found.

## Category 7: Suspicious Patterns

No qualifying commits found.
