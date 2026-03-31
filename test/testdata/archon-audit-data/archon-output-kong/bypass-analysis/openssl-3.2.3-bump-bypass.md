# OpenSSL 3.2.3 Bypass Analysis

## Patch summary
- **What was fixed:** Upstream OpenSSL CVEs via version bump from 3.2.1 to 3.2.3.
- **Mechanism:** Dependency-only update in build metadata; no Kong code changes.
- **Assumptions:** Runtime links against the bundled OpenSSL built from the pinned version.

## Bypass verdict
**relocated**

## Evidence / potential bypass vectors
- **Runtime linkage overrides:** If the runtime loads system or vendor OpenSSL older than 3.2.3, the fixed behavior is bypassed.
- **Binary reuse:** Existing binaries built against 3.2.1 remain vulnerable until rebuilt with 3.2.3.

## Cluster ID
openssl-3.2.x-bump-2024
