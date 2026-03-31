## CROSS-01: Remote User header trust enables impersonation

Source-A: PH-05 from backward-reasoner (round-1-hypotheses.md)
Source-B: PH-01 from contradiction-reasoner (round-2-hypotheses.md)
Connection: Both target `remote_user_auth.login` and the same trust boundary (proxy header → session). They describe the same path with external header injection.
Combined hypothesis: If edge proxies fail to strip `REMOTE_USER_HEADER`, any client can impersonate any user via `/remote_user/login`, leading to account takeover.
Test direction for causal-verifier: Confirm whether any in-app IP allowlist or signed header mechanism exists; check if request path is reachable without upstream proxy.

## CROSS-02: Remote User header trust + internal hop escalation

Source-A: PH-05 from backward-reasoner (round-1-hypotheses.md)
Source-B: PH-02 from contradiction-reasoner (round-2-hypotheses.md)
Connection: Same code path and boundary; PH-02 highlights internal-service spoofing of the header.
Combined hypothesis: Any trusted internal hop (proxy or service) can impersonate arbitrary users by setting the Remote User header, making header provenance a single point of failure.
Test direction for causal-verifier: Identify whether header provenance is enforced (mTLS, signed headers) or only relies on network placement.

## CROSS-03: JIT provisioning expands unauthorized org membership

Source-A: PH-02 from backward-reasoner (round-1-hypotheses.md)
Source-B: PH-03 from contradiction-reasoner (round-2-hypotheses.md)
Connection: Both describe JIT provisioning via IdP claims (OAuth/JWT) with no pre-existing user approval.
Combined hypothesis: JIT provisioning across OAuth/JWT allows any valid IdP principal within the accepted domain/issuer to create a Redash account, bypassing admin onboarding controls.
Test direction for causal-verifier: Verify org settings for domain allowlist and whether account creation is gated by admin approval or group membership checks.

## CROSS-04: SAML IdP-initiated flow + CSRF exemption enables login CSRF

Source-A: PH-03 from backward-reasoner (round-1-hypotheses.md)
Source-B: PH-04 from contradiction-reasoner (round-2-hypotheses.md)
Connection: Same endpoint `saml_auth.idp_initiated`; PH-04 highlights CSRF-exempt POSTs, PH-03 assumes forged assertions.
Combined hypothesis: If SAML responses can be accepted without strong binding to the intended session (and CSRF is exempt), a crafted IdP response can log a victim into an attacker-controlled account.
Test direction for causal-verifier: Check SAML response validation (signature, audience, recipient) and whether IdP-initiated POST is bound to a request or session.
