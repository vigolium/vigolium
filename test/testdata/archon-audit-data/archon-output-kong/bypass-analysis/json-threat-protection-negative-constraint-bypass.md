# JSON Threat Protection Negative Constraint Bypass Analysis

## Patch summary
- **What was fixed:** Normalizes negative constraint values to `nil` before validation to avoid unsafe default interpretation in lua-resty-json-threat-protection.
- **Mechanism:** Input normalization in the validator call path; no changes to library internals.

## Bypass verdict
**sound**

## Evidence
- Normalization occurs before calling `validator.validate`, preventing negative values from being treated as zero or other unsafe defaults.
- No alternate call sites are introduced in the diff; the validator path remains consistent.

## Cluster ID
json-threat-protection-negative-constraint-2024
