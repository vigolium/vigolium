# Bypass Analysis: ec9d13d10 - CVE Allowlist Validation

**Commit:** ec9d13d107010d756ef8f8d2f0989d4703ba25eb
**Cluster ID:** allowlist-validation-2025-06
**Patch Summary:**
Adds pre-storage validation in `src/pkg/allowlist/validator.go` `Validate()` to
reject items where the CVE ID is empty or composed entirely of ASCII whitespace
(`strings.TrimSpace` returns `""`). Duplicate-entry detection was already
present; the patch adds the empty-string guard immediately before it.
The Angular frontend components (`security.component.ts`,
`project-policy-config.component.ts`) also gained a client-side `.filter(id =>
id.length > 0)` step so whitespace tokens are stripped before the POST body is
assembled.

---

## Bypass Verdict: BYPASSABLE

Two independent bypass paths survive the patch.

---

## Finding 1: Normalization Inconsistency Enables Duplicate-Entry Bypass

**Severity:** Medium  
**Location:** `src/pkg/allowlist/validator.go`, lines 49-59

The patch computes a trimmed copy of the CVE ID to gate the emptiness check, but
the deduplication map is keyed on the **raw, untrimmed** value:

```go
cveID := strings.TrimSpace(it.CVEID)   // trimmed – used only for empty check
if cveID == "" {
    return &invalidErr{...}
}
// Duplicate check uses it.CVEID (raw), NOT cveID (trimmed)
if _, ok := m[it.CVEID]; ok {
    return &invalidErr{...}
}
m[it.CVEID] = struct{}{}
```

An attacker may submit an allowlist payload like:

```json
{
  "items": [
    {"cve_id": "CVE-2021-44228"},
    {"cve_id": " CVE-2021-44228"}
  ]
}
```

Both items pass the emptiness check (neither trims to `""`).  The dedup map
keys are `"CVE-2021-44228"` and `" CVE-2021-44228"` — different strings — so no
duplicate error is raised and both entries reach the database.

At query time `CVESet.Contains()` performs an exact-string map lookup against
scanner-reported IDs (which carry no leading/trailing whitespace).  The padded
entry `" CVE-2021-44228"` will **never match** any real scanner finding.  The
non-padded entry `"CVE-2021-44228"` will match and correctly bypass the
vulnerability gate.

The practical security impact is limited: the entry with the leading space is
dead weight, but it does mean the validator emits no error for a logically
inconsistent allowlist and the stored data is silently corrupted.  More
critically, the same trick can be used to insert a CVE ID that _appears_ to be
in the list in the UI but is ineffective (i.e., the opposite exploit: a
malicious admin could insert a padded entry to make an audit-log look clean
while the real vulnerability is not bypassed).

**Root cause:** `cveID` (trimmed) is never stored back to `it.CVEID`, and the
map uses the original value. The fix should normalise the ID before both the
empty check and the dedup check:

```go
// Correct pattern
cveID := strings.TrimSpace(it.CVEID)
if cveID == "" { ... }
if _, ok := m[cveID]; ok { ... }
m[cveID] = struct{}{}
```

---

## Finding 2: Unicode Zero-Width / Invisible Characters Bypass the Empty-ID Check

**Severity:** High  
**Location:** `src/pkg/allowlist/validator.go`, line 49-52

`strings.TrimSpace` in Go trims Unicode code points reported as whitespace by
`unicode.IsSpace()`.  Several visually-invisible characters are **not** covered
by `unicode.IsSpace` and therefore survive `TrimSpace`:

| Character | Code point | TrimSpace result |
|-----------|-----------|-----------------|
| Zero-width space | U+200B | not trimmed — survives |
| Zero-width non-joiner | U+200C | not trimmed — survives |
| Zero-width joiner | U+200D | not trimmed — survives |
| Soft hyphen | U+00AD | not trimmed — survives |
| Null byte | U+0000 | not trimmed — survives |

A payload such as:

```json
{"cve_id": "\u200B"}
```

passes `strings.TrimSpace` returning `"\u200b"` (non-empty), so the emptiness
guard does not fire. The item is accepted and stored. At lookup time,
`CVESet.Contains(v.ID)` will never match because real scanner CVE IDs contain no
zero-width spaces, so the entry is permanently inert — but it bypasses the
validation gate entirely.

More dangerous: a CVE ID like `"CVE-2021-44228\u200B"` is visually identical to
`"CVE-2021-44228"` in every UI rendering context (HTML, terminal, log line) yet
is a distinct string. An attacker with project-admin rights could:

1. Insert `"CVE-2021-44228\u200B"` into the allowlist.
2. The UI and audit logs show `CVE-2021-44228` as allowlisted.
3. The vulnerable middleware `allowlist.Contains(v.ID)` never matches the
   scanner-reported `"CVE-2021-44228"` (no trailing zero-width space).
4. The vulnerability gate therefore **blocks** the image pull — but the audit
   trail shows the CVE as explicitly allowlisted, creating confusion or covering
   tracks.

Alternatively an attacker could use this to inject a _real_ bypass: insert both
`"CVE-2021-44228"` (which will be blocked as a duplicate if it already exists)
and, to add a second copy as a decoy, insert `"CVE-2021-44228\u200B"` which
passes dedup check and emptiness check.

**Root cause:** The validation only checks `strings.TrimSpace`, which does not
cover non-breaking Unicode invisibles. The fix should additionally reject any
CVE ID containing non-printable or zero-width Unicode code points, e.g. via
`strings.IndexFunc(cveID, func(r rune) bool { return !unicode.IsPrint(r) }) >= 0`.

---

## Finding 3: Client-Side Filtering Is Not the Security Boundary

**Severity:** Informational  
**Location:** `src/portal/src/app/base/.../security.component.ts`,
`src/portal/src/app/base/.../project-policy-config.component.ts`

The frontend `addToSystemAllowlist()` and `addToProjectAllowlist()` methods now
filter empty tokens before building the POST body.  This is defence-in-depth for
the UI flow only.  The REST API endpoints (`PUT /api/v2.0/system/CVEAllowlist`
and `PUT /api/v2.0/projects/{id}`) accept JSON bodies directly; a raw API
caller (curl, Burp, automation) bypasses the Angular filtering completely.  The
server-side `Validate()` is the true enforcement point, and Findings 1 and 2
above demonstrate it is not sound.

---

## Finding 4: No Format/Pattern Validation on CVE IDs

**Severity:** Low  
**Location:** `src/pkg/allowlist/validator.go`

Neither before nor after the patch does `Validate()` enforce that the CVE ID
matches the canonical format `CVE-[YEAR]-[SEQUENCE]`.  Any non-empty,
non-whitespace string is accepted (e.g., `"totally-not-a-cve"`,
`"../../../etc/passwd"`, `"<script>"`).  This is an unrelated gap but worth
noting: the patch description says "ensure the CVE ID is valid" yet no format
validation exists.

---

## Alternate Entry Points Assessed

| Entry point | Validation applied? | Notes |
|-------------|---------------------|-------|
| `PUT /api/v2.0/system/CVEAllowlist` (handler: `sys_cve_allowlist.go`) | Yes — calls `mgr.SetSys()` → `Set()` → `Validate()` | Covered |
| `PUT /api/v2.0/projects/{id}` (handler: `project.go UpdateProject`) | Yes — calls `projectCtl.Update()` → `allowlistMgr.Set()` → `Validate()` | Covered |
| `allowlist.Manager.CreateEmpty()` | N/A — creates empty list, no items | Safe |
| Direct DAO (`dao.Set()`) call | No validation — bypasses `manager.Set()` | No known public caller bypasses manager, but internal code could |

All public API paths appear to go through `manager.Set()` which calls `Validate()`.  The DAO layer has no validation of its own; any future code that calls `dao.Set()` directly will bypass all checks.

---

## Summary

The patch correctly closes the original CVE (empty/space-only CVE IDs accepted
at the Go backend). However:

1. **[BYPASSABLE - Medium]** Normalization inconsistency: the dedup map uses the
   raw (untrimmed) CVEID while the emptiness check uses the trimmed value.
   Whitespace-padded duplicates like `" CVE-2021-1234"` bypass duplicate
   detection.

2. **[BYPASSABLE - High]** Unicode invisible characters (U+200B, U+200C,
   U+200D, U+00AD, null byte) are not stripped by `strings.TrimSpace` and pass
   the empty-check guard, allowing semantically empty or visually deceptive CVE
   IDs to be stored.

3. **[Informational]** Client-side filtering in Angular components is not a
   security control; the REST API accepts arbitrary JSON.

4. **[Low]** No CVE format/pattern validation exists despite the patch comment
   claiming to "ensure the CVE ID is valid."

**Undisclosed tag:** N/A (advisory exists)
