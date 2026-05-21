# Triage and Prerequisite Rules

Purpose: define **what qualifies** as a reportable issue and how to prioritize it.  
Out of scope: deep-analysis methodology and report output templates.

## Severity Priority

1. CRITICAL
2. HIGH
3. MEDIUM (secondary pass only)

Low severity findings are eliminated from the audit pipeline entirely. Drop them at whichever phase
first determines their severity (Phase 5, 7, or 8). Never carry a Low finding to Phase 12 or
Phase 15. The final audit report covers Medium, High, and Critical findings only.

If no path to material impact exists, do not report.

## Prerequisite Minimums

Every finding must state:

- Attacker starting position
- Required capabilities
- Trust boundary crossed
- Concrete attacker gain

## Capability Validity Rules

Treat findings as invalid when prerequisites already imply environment compromise:

- Write access to app config/data files
- Control over CI/CD or deployment infrastructure
- Control over runtime environment variables
- Ownership of unrelated external infrastructure as the sole prerequisite

Escalate only if the code under review provides a realistic path to gain that prerequisite.

## Token and Secret Claims

Do not treat "token possession enables access" as a finding by itself.

Report only when there is a feasible acquisition path, such as:

- Exfiltration via XSS/injection
- Leakage to logs, URLs, telemetry, or third-party endpoints
- Misconfiguration that exposes secret material

## Noise Filters

Deprioritize unless chained to clear impact:

- CORS weakness without data exposure/state change
- Missing rate limiting without abuse chain
- Enumeration without takeover or sensitive-data access
- Verbose errors without sensitive disclosure
- Surface-only scanner hits without source-to-sink evidence

## Threat-Model Alignment Rule

Attack vectors are selected by project threat model and attack surface:

- AV:N often applies to internet-facing systems
- Local/adjacent/physical vectors may be in-scope for CLI, desktop, or embedded targets

The report decision should follow project context, not a fixed AV requirement.

## Bug Bounty Scope Gate

Before advancing a finding to Phase 12 or Phase 15, confirm all five:

- [ ] Target (domain, binary, repo, service) is explicitly listed in-scope for the program
- [ ] Bug class is not in the program's exclusion list (e.g., "rate limiting not accepted", "self-XSS out of scope")
- [ ] Test method used is permitted (e.g., no automated scanning if prohibited, no testing on production if not allowed)
- [ ] Finding is not a known, already-reported, or recently-patched duplicate (check public disclosures and changelog)
- [ ] Severity meets the program's minimum threshold (some programs reject informational and low)

If `vigolium-results/bounty-scope.md` was captured during pre-audit setup, cross-reference it here. If scope is unclear, mark the finding `OUT OF SCOPE (scope-unclear)` and do not report until confirmed.

## Severity Calibration

Default-low principle: start every finding at MEDIUM. Require evidence to upgrade.

**Upgrade to HIGH when all three apply:**
- Remotely triggerable without physical access
- Crosses a meaningful trust boundary (user to admin, tenant to tenant, unauthenticated to authenticated state)
- No significant preconditions beyond normal attacker position

**Upgrade to CRITICAL when all three apply:**
- Achieves RCE, full authentication bypass, or mass data exfiltration
- Unauthenticated or exploitable by any low-privilege user
- Internet-facing or otherwise broadly reachable

**Downgrade signals (apply any that fit):**
- Requires local machine access or physical proximity
- Requires admin or operator-level privilege to trigger
- Requires non-default configuration to be vulnerable
- Impact is confined to the attacker's own session or data
- DoS-only with no confidentiality or integrity impact
- Requires chaining multiple individually-unexploitable issues
- Theoretical cryptographic weakness without a practical exploitation path

When in doubt, record `Severity-Original` and `Severity-Final` in the finding draft and document
the calibration reasoning.

**Low severity elimination**: if downgrade signals reduce a finding to Low severity, assign verdict
`DROP (low severity)` immediately and do not carry it forward. Low findings do not receive
adversarial validation, variant analysis, or a final report entry.

## Claude-Specific FP Awareness

Known patterns where Claude-family models produce false positives in security audits:

1. **Unsafe-looking code without path tracing**: flagging a dangerous function call without confirming attacker-controlled input reaches it
2. **Phantom validation bypass**: claiming validation is missing when it exists in a helper, middleware, or parent caller not immediately visible
3. **Framework protection blindness**: missing ORM parameterization, template auto-escaping, CSRF middleware, or other framework-level controls
4. **Same-origin confusion**: treating same-origin or same-session interactions as cross-trust-boundary attacks
5. **Dependency CVE without reachability**: reporting a CVE in a transitive dependency without confirming the vulnerable function is called with attacker input
6. **Config-as-vulnerability**: reporting insecure default config that is overridden in every realistic deployment or that requires admin access to set
7. **Test and example code**: flagging vulnerabilities in test fixtures, documentation examples, or dev-only scripts not shipped to production
8. **Double-counting**: reporting the same root cause under different surface manifestations as multiple distinct findings

For each finding, explicitly check whether it matches one of the above before assigning `VALID`.

## Bug Bounty Litmus Test

Five questions that must all be answered "yes" before submitting:

1. Can this be reproduced end-to-end in under 30 minutes by someone unfamiliar with the codebase?
2. Does successful exploitation result in a meaningful security impact (data exposure, privilege gain, account takeover, or equivalent)?
3. Is this unintended behavior — not a documented feature, accepted risk, or design decision?
4. Is this distinct from publicly known issues, recent patches, and issues already in the program's disclosure queue?
5. Can the impact be demonstrated concretely, without relying on hypothetical attacker capabilities or theoretical conditions?

If any answer is "no" or "uncertain", hold the finding and investigate further before submission.
