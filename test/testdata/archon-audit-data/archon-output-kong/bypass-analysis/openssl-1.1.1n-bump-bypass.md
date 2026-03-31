# OpenSSL 1.1.1n Bypass Analysis

## Patch summary
- **What was fixed:** OpenSSL security CVEs via version bump to 1.1.1n in `.requirements`.
- **Mechanism:** Dependency-only version update; no Kong code changes.
- **Assumptions:** Build uses the pinned OpenSSL from `.requirements` and links it at runtime.

## Bypass verdict
**relocated**

## Evidence / potential bypass vectors
- **External OpenSSL override:** Deployments that link against system OpenSSL or a vendor-provided OpenSSL can bypass the bump and remain on a vulnerable version.
- **Packaging divergence:** Prebuilt binaries or custom build pipelines that freeze dependencies can ignore the new pin and keep older OpenSSL.

## Cluster ID
openssl-1.1.1n-bump
