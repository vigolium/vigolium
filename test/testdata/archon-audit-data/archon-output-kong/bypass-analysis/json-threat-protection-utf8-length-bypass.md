# JSON Threat Protection UTF-8/Length Bypass Analysis

## Patch summary
- **What was fixed:** Updates lua-resty-json-threat-protection to 0.1.1, adds non-UTF8 rejection, fixes length counting for strings and object entry names to use UTF-8 characters, and improves duplicate key detection.
- **Mechanism:** Library update plus validation error handling changes.

## Bypass verdict
**bypassable**

## Evidence / potential bypass vectors
- **Byte-length amplification:** Limits now enforce character counts. Multi-byte UTF-8 (e.g., 4-byte code points) can keep character counts under configured thresholds while inflating byte size, weakening size-based resource protection.
- **Normalization differentials:** Alternate Unicode representations (escaped vs literal, composed vs decomposed) can lead to validator/consumer disagreements for duplicate key detection and length checks if downstream decoding normalizes differently.
- **Validator scope gaps:** Non-UTF8 rejection only applies when the validator runs. If any code path bypasses validation (content-type variations, streaming body handling, empty-body shortcuts), invalid UTF-8 could still reach downstream handlers.

## Cluster ID
json-threat-protection-utf8-length-2024
