# Round 3 Hypotheses — Auth flows (OAuth, SAML, LDAP, JWT, Remote User)

## PH-07: Remote User header safety is confounded by upstream header stripping

- **Reasoning-Model**: Causal
- **Causal Test**: Confounder
- **Origin**: Round-1 PH-05 | Round-2 PH-01 | Cross-Model CROSS-01 | Trust-Assumption
- **Target**: `redash/authentication/remote_user_auth.py:19` — `login`
- **Attacker starting position**: unauthenticated external client with direct app access
- **Causal argument**: The only in-app “protection” is the assumption that an upstream proxy overwrites/strips `REMOTE_USER_HEADER`. If that external control is absent (direct IP access, misconfigured edge, or non-proxied internal route), the header alone is sufficient to reach `create_and_login_user()` and create a session. Safety is therefore confounded by environment, not by code.
- **Real risk**: Header spoofing enables impersonation of any user.
- **Attack input**: `GET /remote_user/login?next=/` with `X-Forwarded-Remote-User: admin@org.example` sent directly to the app listener (bypassing the trusted proxy).
- **Security consequence**: Full account takeover for arbitrary users.
- **Severity estimate**: CRITICAL
- **Read needed**: anatomy sufficient
- **Deepening direction**: Verify whether any in-app allowlist or signed-header verification exists; confirm if the app is reachable without the trusted proxy (direct IP, internal service mesh, or test/staging routes).

---

## PH-08: Internal hop can impersonate users via Remote User header

- **Reasoning-Model**: Causal
- **Causal Test**: Confounder
- **Origin**: Round-2 PH-02 | Cross-Model CROSS-02 | Trust-Assumption
- **Target**: `redash/authentication/remote_user_auth.py:19` — `login`
- **Attacker starting position**: authenticated internal service or compromised reverse proxy
- **Causal argument**: Even when traffic passes through expected infrastructure, header provenance is not enforced in-app (no signed header, mTLS identity binding, or trusted-hop allowlist). Any internal component capable of setting headers becomes a de facto IdP. The observed safety depends entirely on external network trust boundaries.
- **Real risk**: Lateral impersonation across users by any internal hop that can inject the header.
- **Attack input**: Internal request `GET /remote_user/login?next=/queries` with `X-Forwarded-Remote-User: admin@org.example` from a trusted service.
- **Security consequence**: Privilege escalation to arbitrary users from within the internal network.
- **Severity estimate**: HIGH
- **Read needed**: anatomy sufficient
- **Deepening direction**: Identify which internal components can inject the header and whether header signing or mTLS-based provenance is enforced at any layer.

---

## PH-09: JIT provisioning guard is dormant; any IdP principal in allowed scope can self-provision

- **Reasoning-Model**: Causal
- **Causal Test**: Counterfactual
- **Origin**: Round-1 PH-02 | Round-1 PH-06 | Round-2 PH-03 | Cross-Model CROSS-03
- **Target**: `redash/authentication/__init__.py:271` — `create_and_login_user`
- **Attacker starting position**: unauthenticated user with a valid IdP token (OAuth/JWT)
- **Causal argument**: The remaining “protection” is domain/org verification (e.g., `verify_profile` or issuer/audience checks). In normal operation, legitimate IdP principals from the allowed domain/issuer always satisfy this check, meaning the guard is rarely exercised against adversarial input. Because there is no in-app approval gate after the check, the control is effectively dormant and does not causally prevent unauthorized membership.
- **Real risk**: Any valid IdP principal within the accepted domain/issuer can self-provision a Redash account, bypassing admin onboarding or explicit allowlists.
- **Attack input**: OAuth callback or JWT request for `newcontractor@org.example` with valid issuer/audience; first login triggers `create_and_login_user()`.
- **Security consequence**: Unauthorized organization access by accounts that were never approved in Redash.
- **Severity estimate**: HIGH
- **Read needed**: anatomy sufficient
- **Deepening direction**: Check org settings for explicit allowlists or admin-approval gates after JIT provisioning; verify whether `verify_profile()` or JWT claim checks restrict membership beyond domain/issuer.

---

## PH-10: SAML IdP-initiated flow safety is confounded by IdP-only submission assumption

- **Reasoning-Model**: Causal
- **Causal Test**: Confounder
- **Origin**: Round-1 PH-03 | Round-2 PH-04 | Cross-Model CROSS-04
- **Target**: `redash/authentication/saml_auth.py:109` — `idp_initiated`
- **Attacker starting position**: unauthenticated external client
- **Causal argument**: CSRF is exempted for SSO endpoints; the code assumes only a legitimate IdP can POST a SAMLResponse. If an attacker can cause a victim’s browser to POST a crafted or attacker-account SAMLResponse (e.g., via an auto-submitting form), the absence of in-app request binding makes the “protection” entirely dependent on the IdP boundary, not the app itself.
- **Real risk**: Login CSRF/session confusion where a victim’s browser is authenticated into the attacker’s SSO account.
- **Attack input**: Malicious web page that auto-submits `SAMLResponse=<attacker-assertion>` to `/saml/<org>/idp_initiated`.
- **Security consequence**: Victim operates under the attacker’s account, enabling data leakage and action mix-ups.
- **Severity estimate**: MEDIUM
- **Read needed**: anatomy sufficient
- **Deepening direction**: Verify whether SAML response validation binds to relay state, audience, or session context; confirm if SameSite cookies or referrer checks mitigate cross-site POSTs.

---

## Coverage Check

| Round 1+2 Finding | Intervention tested? | Counterfactual tested? | Confounder tested? | New hypothesis? |
|-------------------|:-:|:-:|:-:|:-:|
| Round-1 PH-01 | YES | YES | YES | NO |
| Round-1 PH-02 | YES | YES | YES | PH-09 |
| Round-1 PH-03 | YES | YES | YES | PH-10 |
| Round-1 PH-04 | YES | YES | YES | NO |
| Round-1 PH-05 | YES | YES | YES | PH-07 |
| Round-1 PH-06 | YES | YES | YES | PH-09 |
| Round-2 PH-01 | YES | YES | YES | PH-07 |
| Round-2 PH-02 | YES | YES | YES | PH-08 |
| Round-2 PH-03 | YES | YES | YES | PH-09 |
| Round-2 PH-04 | YES | YES | YES | PH-10 |
| Round-2 PH-05 | YES | YES | YES | NO |

| Cross-Model Seed | Causal analysis done? | Hypothesis generated? |
|-----------------|:-:|:-:|
| CROSS-01 | YES | PH-07 |
| CROSS-02 | YES | PH-08 |
| CROSS-03 | YES | PH-09 |
| CROSS-04 | YES | PH-10 |

| Trust Assumption | Confounder test done? | Hypothesis generated? |
|----------------|:-:|:-:|
| `redash/handlers/authentication.py:74-87` — password present on POST | YES | NO |
| `redash/handlers/authentication.py:152-155` — email exists on POST | YES | NO |
| `redash/handlers/authentication.py:195-196` — email/password exist | YES | NO |
| `redash/authentication/__init__.py:81-83` — `query_id` in `view_args` | YES | NO |
| `redash/authentication/__init__.py:177-183` — JWT claims include `iss`/`aud` | YES | NO |
| `redash/authentication/google_oauth.py:20-24` — `profile["email"]` has `@` | YES | NO |
| `redash/authentication/google_oauth.py:132` — `profile["picture"]` present | YES | NO |
| `redash/authentication/saml_auth.py:127-131` — SAML `FirstName`/`LastName` present | YES | NO |
| `redash/authentication/ldap_auth.py:46` — POST provides email/password | YES | NO |
| `redash/authentication/remote_user_auth.py:28` — trusted header is email | YES | PH-07 / PH-08 |
| `redash/authentication/jwt_auth.py:74-75` — JWT payload includes `iss` | YES | NO |
| `redash/authentication/account.py:11-15` — `SECRET_KEY` usable | YES | NO |
| `redash/authentication/org_resolving.py:18` — org slug lookup succeeds | YES | NO |
