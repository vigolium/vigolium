# Security Audit Report: grafana/grafana
=========================================

**Repository**: grafana/grafana  
**Commit audited**: bb41ac0c85d854e32cb19874fb4b3f17163179a8  
**Branch**: main  
**Audit date**: 2026-04-11  
**Audit mode**: Deep (11-phase, swarm-orchestrated)  
**Model**: claude-sonnet-4-6[1m]  
**Auditor**: Archon Audit System v1 (Phase 11 — Report Assembly)

---

## Executive Summary

This deep security audit of the Grafana OSS repository identified **32 confirmed
findings** across HIGH and MEDIUM severity categories (no CRITICAL findings after
adversarial de-escalation). Four parent findings carry HIGH severity; three have
been verified with executed proofs-of-concept against live Docker environments.

The most significant risk cluster is the **public dashboard credential disclosure
chain**. A residual gap in the CVE-2026-27877 patch allows unauthenticated internet
users to retrieve decrypted datasource credentials — including plaintext passwords
and HTTP BasicAuth header values — from the `/bootdata/:accessToken` and
`/api/frontend/settings` endpoints. The patch is defeated via three independent
injection points in the dashboard JSON parser (template variables, panel datasource
fields, and query target datasource fields), all sharing the same root cause: the
`DsLookup.ByRef()` fallback at `ds_lookup.go:129` returns any UID unchanged when
the lookup map is empty. This makes the CVE fix structurally ineffective.

A notable MEDIUM finding (H6), confirmed with an executed PoC demonstrating admin
impersonation, shows that enabling Grafana's auth-proxy feature without an explicit
IP allowlist — the out-of-the-box configuration — allows any network-reachable client
to impersonate any user, including admin, via a single HTTP header. Cold verification
downgraded this from HIGH to MEDIUM because the auth proxy feature is disabled by
default (opt-in), though the insecure empty-allowlist behavior is activated the moment
an operator turns it on.

Below the HIGH tier, 28 MEDIUM findings document a systemic pattern of
defense-in-depth gaps across the SQL expression allowlist engine, alerting
notification schema versioning, plugin header passthrough, and Kubernetes
admission webhook bypass conditions. Three findings originally classified HIGH were
downgraded to MEDIUM by adversarial cold verification (H1 — intentional design,
H6 — opt-in feature, H7 — non-default shared-JWKS deployment). One finding (H5)
was ruled a FALSE POSITIVE and is excluded from the confirmed count.

Remediation priority should follow the same order: patch the public dashboard
credential exposure chain first (H3/H4 share a single code fix; the same fix also
closes H8 and H9), then address the auth-proxy allowlist default (H6), then work
through the MEDIUM cluster beginning with the SQL expression allowlist gaps that
could enable scheduled denial-of-service if combined with alerting rules.

---

## Methodology Summary

This audit was conducted using the Archon 11-phase deep audit framework with
parallel swarm orchestration:

- **Phase 1 — Advisory Intelligence**: Collection of 42 first-party Grafana CVEs
  and GHSAs from 2024–2026, plus 15 from 2022–2023 for pattern analysis and 20+
  dependency CVEs. Sources: GitHub Advisories API, OSV API, NVD API, Git
  CHANGELOG.

- **Phase 2 — Bypass Analysis**: Architecture and dependency inventory; attack
  surface boundary mapping; identification of high-heat components from advisory
  history.

- **Phase 3 — Knowledge Base (DFD/CFD)**: Threat modeling with data-flow and
  call-flow diagram slices for authentication, public dashboards, datasource proxy,
  SQL expressions, and alerting subsystems.

- **Phase 4 — Static Analysis**: CodeQL Go and JavaScript database creation;
  structural entry-point and sink extraction (42 raw SAST findings); custom
  Semgrep Pro rules targeting Grafana-specific patterns. Artifacts: CodeQL query
  suites, Semgrep rule sets, flow-path reports.

- **Phase 5 — Spec Gap Analysis**: Manual review of API contracts versus
  implementation, identifying access-control omissions and schema drift.

- **Phase 6 — Knowledge Base (Spec Gaps)**: Documented specification-vs-code
  divergences for public dashboard endpoints, provisioning admission webhooks, and
  alerting schema versioning.

- **Phase 7 — Commit Reconnaissance**: Review of recent commits to identify
  security-adjacent changes and partial fixes.

- **Phase 8 — Review Chambers (Phase 8 findings)**: Three multi-agent debate
  chambers (Attack Ideator, Code Tracer, Devil's Advocate, Chamber Synthesizer)
  operating on the high-heat threat clusters identified in Phases 1–6. Generated
  45 hypotheses; 15 promoted to VALID findings.

- **Phase 9 — Cold Verification (P9-LITE)**: Independent adversarial review of all
  HIGH findings. Six reviews conducted; one false positive identified (H5), three
  severity downgradings applied (H1, H6, H7), two confirmed at original severity
  (H3, H4).

- **Phase 10 — Variant Analysis**: Systematic expansion of confirmed attack patterns
  into variant findings across additional code sites. 13 new variant findings
  identified from 5 parent attack patterns.

- **Phase 11 — Report Assembly**: Consolidation, deduplication (H2 dropped as
  cold-verify artifact of H3; H5 excluded as false positive), consistency checks,
  and final report generation.

---

## Summary of Findings

The table below lists all 32 confirmed findings after deduplication and adversarial
review. H2 (duplicate of H3) and H5 (false positive) are excluded.

| ID  | Title                                               | Severity | PoC Status  | Parent |
|-----|-----------------------------------------------------|----------|-------------|--------|
| H3  | Public Dashboard DS_ACCESS_DIRECT Credential Leak   | HIGH     | executed    | --     |
| H4  | CVE-2026-27877 Bypass via ByRef Fallback            | HIGH     | executed    | --     |
| H6  | Auth Proxy Empty Allowlist — Universal Impersonation | MEDIUM   | executed    | --     |
| H8  | Panel Datasource UID Filter Bypass (variant)        | HIGH     | theoretical | H4     |
| H9  | Query Target Datasource UID Filter Bypass (variant) | HIGH     | theoretical | H4     |
| H1  | X-DS-Authorization Header Injection                 | MEDIUM   | theoretical | --     |
| H7  | ExtJWT Empty Audience — Cross-Service Escalation    | MEDIUM   | theoretical | --     |
| M1  | Direct URL Public Exposure via simplejson Reference | MEDIUM   | theoretical | --     |
| M2  | OAuthPassThru Token Theft via Rogue Datasource      | MEDIUM   | theoretical | --     |
| M3  | Public Dashboard Token Enumeration (Missing RBAC)   | MEDIUM   | theoretical | --     |
| M4  | Tag Annotation Org-Wide Scope Leak                  | MEDIUM   | theoretical | --     |
| M5  | Standalone Provisioning Delete Bypass (isStandalone)| MEDIUM   | theoretical | --     |
| M6  | Zanzana Reconciler 61-Minute Revocation Gap         | MEDIUM   | theoretical | --     |
| M7  | Invite Org Quota Bypass (Duplicate Middleware)      | MEDIUM   | theoretical | --     |
| M8  | TempUser SQL UPDATE Missing org_id Constraint       | MEDIUM   | theoretical | --     |
| M9  | WITH RECURSIVE Allowlist Bypass in SQL Engine       | MEDIUM   | executed    | --     |
| M10 | DeleteCollection Provisioning Bypass                | MEDIUM   | theoretical | --     |
| M11 | Alerting Feature Flag Persistence After Disable     | MEDIUM   | theoretical | --     |
| M12 | LDAP EnableUser Hook Bypasses Admin Disable         | MEDIUM   | theoretical | --     |
| M13 | OAuth Insecure Email Lookup Account Takeover        | MEDIUM   | theoretical | --     |
| M14 | JWT Render Key Non-Revocable                        | MEDIUM   | theoretical | --     |
| M15 | Alerting Receiver V1 Schema Secret Leak             | MEDIUM   | theoretical | --     |
| M16 | InfluxDB v0.8 Credential Exposure in Public Dash    | MEDIUM   | theoretical | H3     |
| M17 | X-DS-Authorization via CallResource Passthrough     | MEDIUM   | theoretical | H1     |
| M18 | Direct URL Field Exposure in Public Dash            | MEDIUM   | theoretical | H3     |
| M19 | X-Grafana-User Spoofing via CallResource            | MEDIUM   | theoretical | H1     |
| M20 | SetOp WITH RECURSIVE Walker Skip                    | MEDIUM   | theoretical | M9     |
| M21 | JSON_TABLE ColOpts Expr Bypass                      | MEDIUM   | theoretical | M9     |
| M22 | SELECT Named Window Clause Not Walked               | MEDIUM   | theoretical | M9     |
| M23 | Provisioning RemoveSecrets V1 Schema Gap            | MEDIUM   | theoretical | M15    |
| M24 | Integration V1 Config Assignment Redact Bypass      | MEDIUM   | theoretical | M15    |
| M25 | UpdateContactPoint V1 Redacted Sentinel Bypass      | MEDIUM   | theoretical | M15    |

**Totals**: 32 confirmed findings — HIGH: 4 (all parent findings; 2 variants also HIGH), MEDIUM: 28
(including 3 downgraded from HIGH — H1, H6, H7 — and 13 variants from Phase 10)

---

## Technical Findings Detail

---

### H3 — Public Dashboard DS_ACCESS_DIRECT Credential Leak

- **Severity**: HIGH
- **PoC Status**: executed (Docker, Grafana 12.4.2 / grafana/grafana:latest)
- **Summary**: Any internet user who knows a public dashboard access token can call
  `GET /bootdata/:accessToken` with zero authentication and receive decrypted
  datasource credentials — including HTTP BasicAuth username:password and plaintext
  InfluxDB passwords — in the JSON response. The token is visible in the public
  share URL.
- **Impact**: Decrypted backend datasource credentials (BasicAuth header, plaintext
  InfluxDB password) returned to any unauthenticated caller possessing the share
  URL. Attacker gains direct access to backend data stores bypassing Grafana. Lateral
  movement to production databases or monitoring infrastructure is possible.
- **Root Cause**: `getFSDataSources` (`frontendsettings.go:464`) filters which
  datasources are returned for public callers via `IsPublicDashboardView()` at line
  476, but the credential extraction block at lines 541–577 has no corresponding
  `IsPublicDashboardView()` guard. Credentials for datasources that survive the
  filter are decrypted and serialized unconditionally.
- **Key Code Reference**: `pkg/api/frontendsettings.go:541–577` — `if ds.Access ==
  datasources.DS_ACCESS_DIRECT { DecryptedBasicAuthPassword / DecryptedPassword }`
  executed without public-dashboard context check.
- **Affected Endpoint**: `GET /bootdata/:accessToken` (registered with `reqNoAuth`)
- **CVE Context**: Residual gap in CVE-2026-27877 patch (commit 468a14d).
- **Remediation**: Add `!c.IsPublicDashboardView()` guard around lines 541–577, or
  strip `basicAuth` and `password` fields from the DTO after construction when the
  public dashboard context is active.
- **Detailed Report**: archon/findings/H3-pubdash-credential-exposure/report.md
- **Proof of Concept**: archon/findings/H3-pubdash-credential-exposure/poc.sh
- **Evidence**: archon/findings/H3-pubdash-credential-exposure/evidence/

#### Variants

| ID  | Title                                           | Severity | Location                                                    | PoC Status  |
|-----|-------------------------------------------------|----------|-------------------------------------------------------------|-------------|
| M16 | InfluxDB v0.8 Credential Exposure (public dash) | MEDIUM   | pkg/api/frontendsettings.go:557–565                         | theoretical |
| M18 | Direct URL Field Exposure (public dash)         | MEDIUM   | pkg/api/frontendsettings.go:496–510                         | theoretical |

See individual variant reports:
- archon/findings/M16-pubdash-influxdb08-credential-exposure/draft.md
- archon/findings/M18-pubdash-direct-url-field-exposure/draft.md

---

### H4 — CVE-2026-27877 Bypass via Template Variable Datasource UIDs

- **Severity**: HIGH
- **PoC Status**: executed (unit test + Docker live confirmation, Grafana 12.4.2)
- **Summary**: The CVE-2026-27877 patch restricts public dashboard datasource
  exposure by creating an intentionally empty `DsLookup` and calling `ReadDashboard`
  to identify "used" datasources. The fix is defeated because `DsLookup.ByRef()`
  at `ds_lookup.go:129` returns any non-empty, non-default UID unchanged when the
  lookup maps are empty. A dashboard editor can embed a datasource-type template
  variable whose `current.value` is the UID of any direct-mode datasource in the
  org; that UID passes the filter and its decrypted credentials appear in the public
  frontend settings response for unauthenticated viewers.
- **Impact**: Complete nullification of the CVE-2026-27877 fix for dashboards under
  editor control. Decrypted BasicAuth passwords and InfluxDB credentials for any
  direct-mode datasource in the org are exposed to unauthenticated internet users.
  Privilege escalation: dashboard editors (no datasource admin rights) can exfiltrate
  credentials for datasources they cannot query. Blast radius covers any
  direct-mode datasource UID in the org.
- **Root Cause**: `CreateDatasourceLookup([]*DatasourceQueryResult{})` at
  `frontendsettings.go:851–853` creates empty byUID/byName maps. `ByRef()` iterates
  these maps, finds nothing, then falls through to `return ref` at `ds_lookup.go:129`,
  returning the attacker-supplied UID unchanged. The fix and the function contract
  are incompatible: `ByRef` guarantees it never returns nil for a non-empty UID.
- **Key Code Reference**: `pkg/services/store/kind/dashboard/ds_lookup.go:129` —
  `return ref` fallback when UID not found in empty lookup maps.
- **Remediation**: Pass actual org datasources into `CreateDatasourceLookup` and
  reject UIDs not found, OR add a strict mode to `ByRef` that returns nil when a
  UID is absent, OR remove the `return ref` fallback and audit all callers.
- **Detailed Report**: archon/findings/H4-cve-2026-27877-bypass/report.md
- **Evidence**: archon/findings/H4-cve-2026-27877-bypass/evidence/

#### Variants

| ID | Title                                               | Severity | Location                                                        | PoC Status  |
|----|-----------------------------------------------------|----------|-----------------------------------------------------------------|-------------|
| H8 | Panel Datasource UID Filter Bypass                  | HIGH     | pkg/services/store/kind/dashboard/targets.go:41,56              | theoretical |
| H9 | Query Target Datasource UID Filter Bypass           | HIGH     | pkg/services/store/kind/dashboard/targets.go:78–88              | theoretical |

H8 exploits the bypass via direct panel `datasource` fields (no template variable
needed). H9 exploits it via `targets[].datasource` fields in panel queries. Both
use the same `ByRef` fallback at `ds_lookup.go:129` as H4.

See individual variant reports:
- archon/findings/H8-panel-datasource-uid-filter-bypass/draft.md
- archon/findings/H9-query-target-datasource-uid-filter-bypass/draft.md

---

### H6 — Auth Proxy Empty Allowlist Allows Universal Impersonation

- **Severity**: MEDIUM (downgraded from HIGH by adversarial cold verification;
  requires non-default opt-in; executed PoC confirmed admin impersonation)
- **PoC Status**: executed (Docker, grafana/grafana:11.4.0)
- **Summary**: When Grafana's auth proxy feature is enabled (`[auth.proxy]
  enabled = true`), the IP allowlist (`whitelist`) defaults to an empty string.
  `isAllowedIP()` at `proxy.go:200–202` returns `true` unconditionally when
  `len(c.acceptedIPs) == 0`. Any network-reachable client can authenticate as any
  Grafana user — including admin — by setting a single HTTP header
  (`X-WEBAUTH-USER` by default).
- **Impact**: Complete authentication bypass. Any user, including server
  administrator, can be impersonated with a single HTTP request. With
  `auto_sign_up = true` (default), accounts for arbitrary usernames are auto-created,
  enabling persistence. All Grafana data is accessible: dashboards, datasource
  credentials, alerting configs, API keys, connected data stores. Executed PoC
  confirmed `isAdmin: true` and auto-signup of attacker-chosen account from
  arbitrary IP.
- **Root Cause**: `parseAcceptList` returns nil for empty whitelist string; nil slice
  has length 0; `isAllowedIP` short-circuits to `return true`. The logic
  inverts the intended security posture — an empty allowlist should deny all, not
  allow all.
- **Key Code Reference**: `pkg/services/authn/clients/proxy.go:200–202` —
  `if len(c.acceptedIPs) == 0 { return true }`.
- **Remediation**: Invert the guard to `return false` when `acceptedIPs` is empty,
  or require explicit opt-in to allow-all via a separate config key. Document the
  security risk prominently in the auth proxy configuration reference.
- **Detailed Report**: archon/findings/H6-proxy-auth-empty-allowlist/report.md
- **Evidence**: archon/findings/H6-proxy-auth-empty-allowlist/evidence/

---

### H8 — Panel Datasource UID Filter Bypass (CVE-2026-27877 variant)

- **Severity**: HIGH
- **PoC Status**: theoretical (source code confirmed; same live environment used for
  H4 demonstrates the underlying mechanism)
- **Summary**: The same `ByRef` fallback that enables H4 is also triggered when
  `readpanelInfo` processes the `panels[].datasource` field. A dashboard editor
  sets `panel.datasource.uid` to any direct-mode datasource UID in the org. No
  template variables are required. The UID flows through `addDatasource` ->
  `s.lookup.ByRef(ref)` -> `ds_lookup.go:129` -> `usedUIDs` -> credential
  extraction.
- **Impact**: Simpler attack vector than H4 (no template variable structure
  needed); exposes direct-mode datasource credentials to unauthenticated public
  dashboard viewers. Affects both v1 (panels array) and v2 (elements structure)
  dashboard schemas.
- **Root Cause**: Same as H4 — empty DsLookup at `frontendsettings.go:851–853`;
  `ByRef` fallback at `ds_lookup.go:129`.
- **Key Code Reference**: `pkg/services/store/kind/dashboard/dashboard.go:614` —
  `case "datasource": targets.addDatasource(iter, ...)` in `readpanelInfo`;
  `pkg/services/store/kind/dashboard/targets.go:56` — `s.addRef(s.lookup.ByRef(ref))`
  with empty lookup.
- **Parent Finding**: H4 (same fix resolves H4, H8, and H9 together)
- **Detailed Report**: archon/findings/H8-panel-datasource-uid-filter-bypass/draft.md
- **Evidence**: archon/findings/H8-panel-datasource-uid-filter-bypass/evidence/

---

### H9 — Query Target Datasource UID Filter Bypass (CVE-2026-27877 variant)

- **Severity**: HIGH
- **PoC Status**: theoretical (source code confirmed)
- **Summary**: The third distinct injection point for the CVE-2026-27877 bypass.
  Dashboard editor controls `panels[].targets[].datasource`. `addTarget` calls
  `addDatasource` for each target's datasource field; `addDatasource` calls
  `s.lookup.ByRef(ref)` with the empty DsLookup; the fallback at `ds_lookup.go:129`
  returns the arbitrary UID unchanged. The target panel itself can use a legitimate
  datasource — only the query target needs the attacker-controlled UID.
- **Impact**: Third independent injection point for the same bypass. If a future
  patch addresses only template variables (H4) or only panel-level datasource fields
  (H8), this target-level variant remains exploitable. Makes comprehensive fix
  harder — all three callsites to `ByRef` within the `ReadDashboard` flow must be
  addressed simultaneously.
- **Root Cause**: Same as H4 and H8.
- **Key Code Reference**: `pkg/services/store/kind/dashboard/targets.go:72–88` —
  `addTarget` calls `addDatasource` for `targets[].datasource`; `ds_lookup.go:129`
  — fallback passthrough.
- **Parent Finding**: H4
- **Detailed Report**: archon/findings/H9-query-target-datasource-uid-filter-bypass/draft.md
- **Evidence**: archon/findings/H9-query-target-datasource-uid-filter-bypass/evidence/

---

### H1 — X-DS-Authorization Header Injection (downgraded to MEDIUM)

- **Severity**: MEDIUM (downgraded from HIGH by adversarial cold verification;
  intentional feature used by Grafana's own frontend)
- **PoC Status**: theoretical
- **Summary**: Any authenticated user with `datasources:query` permission (Viewer
  role by default) can inject an arbitrary `Authorization` header value into outbound
  datasource proxy requests by setting `X-DS-Authorization` on their Grafana API
  request. The proxy director reads this header and overwrites the stored datasource
  credentials on the outbound request.
- **Impact**: In multi-tenant deployments where shared backend datasources use
  `Authorization`-header-based namespace isolation (Prometheus, Loki,
  Elasticsearch), any Viewer can access other tenants' data. The header is deleted
  after reading, leaving no trace in proxy logs.
- **Root Cause**: `ds_proxy.go:230–234` reads `X-DS-Authorization` and overwrites
  the outbound `Authorization` header unconditionally. `GetAuthHTTPHeaders()` does
  not include `X-DS-Authorization` in its strip list, so the header survives
  inbound middleware.
- **Key Code Reference**: `pkg/api/pluginproxy/ds_proxy.go:230–234` — `dsAuth :=
  req.Header.Get("X-DS-Authorization"); req.Header.Set("Authorization", dsAuth)`.
- **Adversarial Note**: This is an intentional Grafana design feature introduced in
  2016 (PR #4832). The frontend (`backend_srv.ts:310–313`) actively uses it.
  Security impact is deployment-topology-specific. Downgraded from HIGH to MEDIUM.
- **Detailed Report**: archon/findings/H1-xds-auth-header-injection/draft.md
- **Evidence**: archon/findings/H1-xds-auth-header-injection/evidence/

#### Variants

| ID  | Title                                         | Severity | Location                                   | PoC Status  |
|-----|-----------------------------------------------|----------|--------------------------------------------|-------------|
| M17 | X-DS-Authorization via CallResource path      | MEDIUM   | pkg/api/plugin_resource.go:97–116          | theoretical |
| M19 | X-Grafana-User Spoofing via CallResource       | MEDIUM   | pkg/services/pluginsintegration/pluginsintegration.go:212–213 | theoretical |

See individual variant reports:
- archon/findings/M17-xds-auth-callresource-passthrough/draft.md
- archon/findings/M19-xgrafana-user-spoofing-callresource/draft.md

---

### H7 — ExtJWT Empty Audience — Cross-Service Identity Escalation (downgraded to MEDIUM)

- **Severity**: MEDIUM (downgraded from HIGH; requires non-default shared-JWKS
  deployment with an existing valid access-policy token)
- **PoC Status**: theoretical
- **Summary**: The ExtendedJWT auth client at `ext_jwt.go:58–60` creates an ID
  token verifier with an empty `AllowedAudiences` configuration, explicitly
  skipping audience validation. In shared-JWKS deployments, an ID token issued for
  another service in the same namespace can be presented to Grafana. The
  `TypeRenderService` subject handling at lines 184–190 grants Admin role to any
  token with `sub=render:<anything>`.
- **Impact**: Privilege escalation to Admin role in Grafana's default organization
  in shared-JWKS deployment topologies. Grants full administrative access including
  user/org administration and stored datasource credentials.
- **Root Cause**: `authlib.NewIDTokenVerifier(authlib.VerifierConfig{}, keys)` at
  `ext_jwt.go:58` — empty `VerifierConfig` means `AnyAudience` is empty, so go-jose
  skips audience validation. Namespace cross-check is the only remaining control.
- **Key Code Reference**: `pkg/services/authn/clients/ext_jwt.go:58–60, 184–190`.
- **Detailed Report**: archon/findings/H7-extjwt-empty-audience/draft.md
- **Evidence**: archon/findings/H7-extjwt-empty-audience/evidence/

---

### M1 — Direct URL Public Exposure via simplejson Reference

- **Severity**: MEDIUM
- **PoC Status**: theoretical
- **Summary**: Internal datasource backend URLs (Prometheus, Amazon Prometheus,
  Azure Prometheus) are exposed to unauthenticated public dashboard viewers via the
  `jsonData.directUrl` field in the frontend settings response. This occurs because
  `ds.JsonData.Set("directUrl", ds.URL)` at `frontendsettings.go:594–596` modifies
  the same underlying map that was returned by `ds.JsonData.MustMap()` and assigned
  to `dsDTO.JSONData` at line 538, due to simplejson's reference semantics. No
  `IsPublicDashboardView()` guard exists.
- **Impact**: Internal network topology disclosure to unauthenticated viewers
  (internal hostnames, ports, cloud endpoint URLs). No credential exposure but
  enables reconnaissance for follow-on attacks.
- **Root Cause**: `pkg/api/frontendsettings.go:538` — `dsDTO.JSONData =
  ds.JsonData.MustMap()` returns a reference; line 594–596 mutates the same map
  with the raw URL. No public dashboard guard.
- **Key Code Reference**: `pkg/api/frontendsettings.go:538, 594–596`.
- **Detailed Report**: archon/findings/M1-directurl-public-exposure/draft.md
- **Evidence**: archon/findings/M1-directurl-public-exposure/evidence/

---

### M2 — OAuthPassThru Token Theft via Rogue Datasource

- **Severity**: MEDIUM
- **PoC Status**: theoretical
- **Summary**: An org admin can create a datasource pointing to an
  attacker-controlled URL with `oauthPassThru` enabled. When any OAuth-authenticated
  user queries through this datasource, their OAuth access token and OIDC ID token
  are forwarded to the attacker's server. The OSS `DataSourceRequestValidator` is
  a no-op and `DataProxyWhiteList` is empty by default, providing no SSRF or URL
  destination validation.
- **Impact**: OAuth token exfiltration from any user who queries the rogue
  datasource. Tokens can grant access to external services (GitHub, Google, cloud
  providers) the victim has authorized Grafana to use.
- **Root Cause**: `pkg/api/pluginproxy/ds_proxy.go:266–275` — OAuth token
  extraction without destination validation; `pkg/services/validations/oss.go:11` —
  `OSSDataSourceRequestValidator.Validate` returns nil unconditionally.
- **Key Code Reference**: `pkg/api/pluginproxy/ds_proxy.go:266–275`.
- **Detailed Report**: archon/findings/M2-oauthpassthru-token-theft/draft.md
- **Evidence**: archon/findings/M2-oauthpassthru-token-theft/evidence/

---

### M3 — Public Dashboard Token Enumeration (Missing RBAC)

- **Severity**: MEDIUM
- **PoC Status**: theoretical
- **Summary**: `GET /api/dashboards/public-dashboards` (ListPublicDashboards) is
  protected only by `middleware.ReqSignedIn` — no RBAC permission check. Any
  authenticated org member (including Viewers) can enumerate all public dashboard
  access tokens for their organization. Combined with H3/H4, this creates an
  attack chain: any Viewer discovers tokens, then exploits the credential leak.
- **Impact**: Any authenticated org member can obtain all public dashboard access
  tokens. Combined with the credential disclosure chain (H3/H4), this reduces the
  attacker prerequisite from "knows a share URL" to "has any Grafana account."
- **Root Cause**: `pkg/services/publicdashboards/api/api.go:82` — route registered
  with `middleware.ReqSignedIn` only, no `accesscontrol.EvalPermission`.
- **Key Code Reference**: `pkg/services/publicdashboards/api/api.go:82, 113`.
- **Detailed Report**: archon/findings/M3-pubdash-token-enum/draft.md
- **Evidence**: archon/findings/M3-pubdash-token-enum/evidence/

---

### M4 — Tag Annotation Org-Wide Scope Leak

- **Severity**: MEDIUM
- **PoC Status**: theoretical
- **Summary**: Tag-based annotations configured on public dashboards execute with
  org-wide scope, returning annotation events from ALL dashboards in the organization
  that use matching tags. When `Target.Type == "tags"`, the annotation query sets
  `DashboardID = 0` and `DashboardUID = ""`, causing the annotation repository to
  search org-wide. This exposes potentially sensitive operational annotations
  (incident notes, deployment markers, on-call comments) from private dashboards to
  unauthenticated public dashboard viewers.
- **Impact**: Sensitive operational information from private dashboards (incident
  timelines, deployment events, on-call notes) visible to unauthenticated users.
- **Root Cause**: `pkg/services/publicdashboards/service/query.go:61–65` —
  `DashboardID = 0`, `DashboardUID = ""` remove dashboard scope from tag-based
  annotation queries.
- **Key Code Reference**: `pkg/services/publicdashboards/service/query.go:61–68`.
- **Detailed Report**: archon/findings/M4-tag-annotation-scope/draft.md
- **Evidence**: archon/findings/M4-tag-annotation-scope/evidence/

---

### M5 — Standalone Provisioning Delete Bypass (isStandalone)

- **Severity**: MEDIUM
- **PoC Status**: theoretical
- **Summary**: In standalone/App Platform deployment mode, the `validateDelete`
  admission webhook at `register.go:343–346` unconditionally skips all
  provisioned-dashboard protection. The code comment explicitly labels this as a
  "HACK." Any user with `dashboards:delete` permission in a standalone deployment
  can delete provisioned dashboards that should be immutable.
- **Impact**: Destruction of infrastructure-managed dashboards in App Platform
  deployments; operators may not realize their "immutable" dashboards can be
  silently deleted.
- **Root Cause**: `pkg/registry/apis/dashboard/register.go:343–346` — `if a.isStandalone
  { return nil }` unconditionally bypasses provisioning protection.
- **Key Code Reference**: `pkg/registry/apis/dashboard/register.go:343–346`.
- **Detailed Report**: archon/findings/M5-standalone-provisioning-bypass/draft.md
- **Evidence**: archon/findings/M5-standalone-provisioning-bypass/evidence/

---

### M6 — Zanzana Reconciler 61-Minute Revocation Gap

- **Severity**: MEDIUM
- **PoC Status**: theoretical
- **Summary**: When Zanzana (OpenFGA-based authorization) is enabled, the permission
  reconciler runs on a 1-hour default interval. Combined with a 60-second RBAC cache
  TTL, revoked permissions remain effective for up to approximately 61 minutes after
  an administrator revokes access. This makes emergency access revocation ineffective
  in Zanzana-enabled deployments.
- **Impact**: Fired employees, compromised accounts, and emergency access revocations
  remain active for up to 61 minutes. Particularly dangerous for high-privilege
  users with access to datasource credentials or alerting configurations.
- **Root Cause**: `pkg/setting/settings_zanzana.go:418` — `zr.Interval =
  reconcilerSec.Key("interval").MustDuration(1 * time.Hour)`.
- **Key Code Reference**: `pkg/setting/settings_zanzana.go:418`.
- **Detailed Report**: archon/findings/M6-zanzana-reconciler-revocation-gap/draft.md
- **Evidence**: archon/findings/M6-zanzana-reconciler-revocation-gap/evidence/

---

### M7 — Invite Org Quota Bypass (Duplicate Middleware)

- **Severity**: MEDIUM
- **PoC Status**: theoretical
- **Summary**: The invite creation route at `POST /api/org/invites` has a duplicate
  `quota(user.QuotaTargetSrv)` middleware check where the second instance should be
  `quota(org.QuotaTargetSrv)`. The org-level user quota is never enforced on invite
  creation, allowing an org admin to create unlimited invitations beyond the
  configured org user limit.
- **Impact**: Org admins can bypass org user quotas, potentially enabling resource
  exhaustion or excessive user provisioning in shared Grafana deployments.
- **Root Cause**: `pkg/api/api.go:353` — `quota(user.QuotaTargetSrv)` duplicated
  instead of `quota(org.QuotaTargetSrv)` (copy-paste error).
- **Key Code Reference**: `pkg/api/api.go:353`.
- **Detailed Report**: archon/findings/M7-invite-org-quota-bypass/draft.md
- **Evidence**: archon/findings/M7-invite-org-quota-bypass/evidence/

---

### M8 — TempUser SQL UPDATE Missing org_id Constraint

- **Severity**: MEDIUM
- **PoC Status**: theoretical
- **Summary**: `UpdateTempUserStatus` at `store.go:30` updates `temp_user` records
  by invite code without an `org_id` constraint. The handler-level org check at
  `org_invite.go:207` is the sole protection against cross-org invite manipulation.
  This single-barrier pattern matches CVE-2024-10452 (invite IDOR) where a similar
  defense was exploited.
- **Impact**: If a future code change removes or bypasses the handler-level check
  (as has happened historically), cross-org invite manipulation becomes possible.
  Structural fragility matching a previously exploited pattern.
- **Root Cause**: `pkg/services/temp_user/tempuserimpl/store.go:30` —
  `UPDATE temp_user SET status=? WHERE code=?` missing `AND org_id=?`.
- **Key Code Reference**: `pkg/services/temp_user/tempuserimpl/store.go:30`.
- **Detailed Report**: archon/findings/M8-tempuser-sql-no-orgid/draft.md
- **Evidence**: archon/findings/M8-tempuser-sql-no-orgid/evidence/

---

### M9 — WITH RECURSIVE Allowlist Bypass in SQL Expression Engine

- **Severity**: MEDIUM
- **PoC Status**: executed (Go test against production codebase)
- **Summary**: The SQL expression allowlist at `parser_allow.go:170–171` permits
  any `*sqlparser.With` AST node unconditionally without inspecting the `Recursive`
  boolean field. Because `Recursive` is a plain Go bool (not an AST child node), it
  is invisible to `sqlparser.Walk`. This allows authenticated users with panel edit
  rights to submit `WITH RECURSIVE` queries that generate up to 100,000 rows
  entirely inside the in-process SQL engine, bypassing both the allowlist and the
  input-cell limit (which sees 0 input frames for recursive CTEs).
- **Impact**: CPU and memory consumption proportional to recursion depth, up to
  100k rows or query timeout per request. If embedded in an alerting rule, becomes
  persistent scheduled DoS that continues after the feature flag is disabled
  (see M11). Third-generation SQL expression security issue after CVE-2024-9264 and
  CVE-2026-28375.
- **Root Cause**: `pkg/expr/sql/parser_allow.go:170` — `case *sqlparser.With:
  return` — `Recursive bool` field never read.
- **Key Code Reference**: `pkg/expr/sql/parser_allow.go:170–171`.
- **Remediation**: Change `case *sqlparser.With: return` to
  `case *sqlparser.With: return !v.Recursive`.
- **Detailed Report**: archon/findings/M9-with-recursive-allowlist-bypass/report.md
- **Evidence**: archon/findings/M9-with-recursive-allowlist-bypass/evidence/

#### Variants

| ID  | Title                                        | Severity | Location                                          | PoC Status  |
|-----|----------------------------------------------|----------|---------------------------------------------------|-------------|
| M20 | SetOp WITH RECURSIVE Walker Skip             | MEDIUM   | pkg/expr/sql/parser_allow.go:130–133              | theoretical |
| M21 | JSON_TABLE ColOpts Expr Bypass               | MEDIUM   | pkg/expr/sql/parser_allow.go:124                  | theoretical |
| M22 | SELECT Named Window Clause Not Walked        | MEDIUM   | pkg/expr/sql/parser_allow.go:127                  | theoretical |

See individual variant reports:
- archon/findings/M20-setop-with-recursive-walker-skip/draft.md
- archon/findings/M21-jsontable-colopts-expr-bypass/draft.md
- archon/findings/M22-select-window-clause-not-walked/draft.md

---

### M10 — DeleteCollection Provisioning Bypass

- **Severity**: MEDIUM
- **PoC Status**: theoretical
- **Summary**: The `validateDelete` admission webhook skips all provisioned-dashboard
  protection for Kubernetes DeleteCollection requests. When a DELETE request targets
  the collection endpoint without specifying a resource name, `a.GetName()` returns
  empty string, triggering an early return at `register.go:338–341` that bypasses
  the provisioning check. Any user with collection-delete permission can bulk-delete
  all dashboards in an org, including provisioned ones.
- **Impact**: Bulk destruction of infrastructure-managed dashboards; bypasses the
  provisioning immutability guarantee.
- **Root Cause**: `pkg/registry/apis/dashboard/register.go:338–341` — `if
  a.GetName() == "" { return nil }` meant to handle non-resource requests, but
  DeleteCollection uses an empty name.
- **Key Code Reference**: `pkg/registry/apis/dashboard/register.go:338–341`.
- **Detailed Report**: archon/findings/M10-deletecollection-provisioning-bypass/draft.md
- **Evidence**: archon/findings/M10-deletecollection-provisioning-bypass/evidence/

---

### M11 — Alerting Feature Flag Persistence After Disable

- **Severity**: MEDIUM
- **PoC Status**: theoretical
- **Summary**: The alerting evaluator caches the expression pipeline at creation time
  via `BuildPipeline()`. The `FlagSqlExpressions` feature flag is checked during
  pipeline construction but not re-checked per evaluation cycle. If an administrator
  disables the flag after a user creates an alerting rule with SQL expressions, the
  existing evaluator continues executing the SQL expression on every evaluation
  schedule indefinitely. Combined with M9, this creates persistent scheduled DoS
  after the admin disables the feature.
- **Impact**: Persistent resource consumption (CPU/memory) that cannot be stopped
  without restarting Grafana or deleting the alerting rule, even after the
  administrator has disabled the feature flag.
- **Root Cause**: `pkg/services/ngalert/eval/eval.go:876` — `BuildPipeline` called
  once at evaluator creation; feature flag not re-checked per evaluation.
- **Key Code Reference**: `pkg/services/ngalert/eval/eval.go:876`.
- **Detailed Report**: archon/findings/M11-alerting-featureflag-persistence/draft.md
- **Evidence**: archon/findings/M11-alerting-featureflag-persistence/evidence/

---

### M12 — LDAP EnableUser Hook Bypasses Admin Disable

- **Severity**: MEDIUM
- **PoC Status**: theoretical
- **Summary**: `EnableUserHook` at `user_sync.go:421–441` unconditionally sets
  `is_disabled=false` for any LDAP-managed user attempting to log in, regardless of
  whether the account was disabled by a Grafana administrator. The database schema
  has only a single `is_disabled` boolean column with no distinction between
  admin-imposed and LDAP-sync-imposed disable. The DB write executes at hook
  priority 20 before other validation hooks, and persists even if the login
  ultimately fails.
- **Impact**: Administrators cannot reliably disable LDAP user accounts for incident
  response. A suspended LDAP user can re-enable their account simply by attempting
  to log in. Undermines emergency access revocation.
- **Root Cause**: `pkg/services/authn/authnimpl/sync/user_sync.go:421–441` —
  `EnableUserHook` unconditionally re-enables the user; single `is_disabled` column
  cannot distinguish admin vs sync disable.
- **Key Code Reference**: `pkg/services/authn/authnimpl/sync/user_sync.go:421–441`.
- **Detailed Report**: archon/findings/M12-ldap-enable-hook-bypass/draft.md
- **Evidence**: archon/findings/M12-ldap-enable-hook-bypass/evidence/

---

### M13 — OAuth Insecure Email Lookup Account Takeover

- **Severity**: MEDIUM
- **PoC Status**: theoretical
- **Summary**: When `oauth_allow_insecure_email_lookup=true` is configured in
  `[auth]`, the OAuth authentication client at `oauth.go:206–210` matches users
  solely by email address instead of requiring AuthID/sub claim matching. An attacker
  controlling an OAuth provider (or any configured provider that allows arbitrary
  email claims) can present any victim's email address during OAuth callback and
  take over the victim's Grafana account.
- **Impact**: Account takeover of any Grafana user whose email the attacker can
  present via an OAuth provider. Requires non-default configuration but is
  explicitly documented as an available option.
- **Root Cause**: `pkg/services/authn/clients/oauth.go:206–210` — email-only
  lookup bypass when `allowInsecureEmailLookup` is enabled.
- **Key Code Reference**: `pkg/services/authn/clients/oauth.go:206–210`.
- **Detailed Report**: archon/findings/M13-oauth-insecure-email-lookup/draft.md
- **Evidence**: archon/findings/M13-oauth-insecure-email-lookup/evidence/

---

### M14 — JWT Render Key Non-Revocable

- **Severity**: MEDIUM
- **PoC Status**: theoretical
- **Summary**: JWT-based render keys cannot be revoked once issued. The
  `jwtRenderKeyProvider.afterRequest()` at `rendering/auth.go:141–143` is
  intentionally a no-op ("do nothing — the JWT will just expire"). A leaked render
  key remains valid for its full JWT lifetime, granting the bearer the ability to
  authenticate as the rendering service with Admin-level OrgRole. The render auth
  client operates at priority 10, preceding session auth at priority 60.
- **Impact**: Leaked render keys provide persistent Admin-equivalent authentication
  until natural JWT expiry. No operator action can revoke an outstanding key.
- **Root Cause**: `pkg/services/rendering/auth.go:141–143` — empty `afterRequest()`
  with no revocation list or one-time-use tracking.
- **Key Code Reference**: `pkg/services/rendering/auth.go:141–143`.
- **Detailed Report**: archon/findings/M14-render-key-non-revocable/draft.md
- **Evidence**: archon/findings/M14-render-key-non-revocable/evidence/

---

### M15 — Alerting Receiver V1 Schema Secret Leak

- **Severity**: MEDIUM
- **PoC Status**: theoretical
- **Summary**: `EncryptReceiverConfigs` at `crypto.go:88` hardcodes `schema.V1`
  when calling `GetSchemaVersionForIntegration()` to discover secret field paths.
  Only secret fields defined in the V1 schema are recognized, encrypted, and moved
  to `SecureSettings`. Any secret field added in V2 or later schema versions remains
  as plaintext in the `Settings` JSON blob. `FilterRead` and `FilterReadDecrypted`
  only suppress the `SecureSettings` map, not the `Settings` body, so V2+ plaintext
  secrets are visible to any user with `ActionAlertingNotificationsRead` (Viewer role).
- **Impact**: Future integration schema additions with secret fields will
  silently escape encryption and be readable by Viewers via alerting provisioning
  API endpoints. This is a systemic schema-evolution vulnerability affecting all
  future integrations.
- **Root Cause**: `pkg/services/ngalert/notifier/crypto.go:88` — hardcoded
  `schema.V1` in `GetSchemaVersionForIntegration` call.
- **Key Code Reference**: `pkg/services/ngalert/notifier/crypto.go:88`;
  `pkg/services/ngalert/notifier/receiver_svc.go:231–235`.
- **Detailed Report**: archon/findings/M15-receiver-v1-schema-secret-leak/draft.md
- **Evidence**: archon/findings/M15-receiver-v1-schema-secret-leak/evidence/

#### Variants

| ID  | Title                                              | Severity | Location                                                       | PoC Status  |
|-----|----------------------------------------------------|----------|----------------------------------------------------------------|-------------|
| M23 | Provisioning RemoveSecrets V1 Schema Gap           | MEDIUM   | pkg/services/ngalert/provisioning/contactpoints.go:661         | theoretical |
| M24 | Integration V1 Config Assignment Redact Bypass     | MEDIUM   | pkg/services/ngalert/notifier/legacy_storage/compat.go:157     | theoretical |
| M25 | UpdateContactPoint V1 Redacted Sentinel Bypass     | MEDIUM   | pkg/services/ngalert/provisioning/contactpoints.go:271         | theoretical |

See individual variant reports:
- archon/findings/M23-provisioning-encrypt-v1-schema-gap/draft.md
- archon/findings/M24-integration-v1-config-assignment-redact-bypass/draft.md
- archon/findings/M25-update-contact-point-v1-redacted-bypass/draft.md

---

### M16 — InfluxDB v0.8 Credential Exposure in Public Dashboard

- **Severity**: MEDIUM
- **PoC Status**: theoretical
- **Summary**: Unauthenticated public dashboard viewers receive decrypted plaintext
  credentials for InfluxDB v0.8 (`influxdb_08`) datasources configured with direct
  mode. The block at `frontendsettings.go:557–565` calls `DecryptedPassword` and
  sets `dsDTO.Username` and `dsDTO.Password` without any `IsPublicDashboardView()`
  guard. This is a co-located variant of H3 affecting the `DS_INFLUXDB_08` branch.
- **Impact**: Same as H3 for InfluxDB v0.8 datasources.
- **Root Cause**: Same as H3 — missing `IsPublicDashboardView()` guard in
  `pkg/api/frontendsettings.go:557–565`.
- **Parent Finding**: H3
- **Detailed Report**: archon/findings/M16-pubdash-influxdb08-credential-exposure/draft.md

---

### M17 — X-DS-Authorization via CallResource Path

- **Severity**: MEDIUM
- **PoC Status**: theoretical
- **Summary**: The `X-DS-Authorization` header injection path exists in the plugin
  backend `CallResource` transport. `makePluginResourceRequest` at
  `plugin_resource.go:97–116` copies all inbound headers verbatim into
  `crReq.Headers`. `ClearAuthHeadersMiddleware` does not strip `X-DS-Authorization`.
  The header survives the full plugin middleware stack and is forwarded to plugin
  backend outgoing HTTP calls via the SDK's `headerMiddleware`.
- **Impact**: Same credential override impact as H1 (MEDIUM), applied to the
  CallResource endpoint (`/api/datasources/:id/resources/*` and
  `/api/plugins/:pluginId/resources/*`).
- **Root Cause**: Same as H1 — `GetAuthHTTPHeaders()` omits `X-DS-Authorization`.
- **Parent Finding**: H1
- **Detailed Report**: archon/findings/M17-xds-auth-callresource-passthrough/draft.md

---

### M18 — Direct URL Field Exposure in Public Dashboard

- **Severity**: MEDIUM
- **PoC Status**: theoretical
- **Summary**: For every datasource configured with `Access: direct`,
  `getFSDataSources` sets `dsDTO.URL` to the raw backend datasource URL without any
  `IsPublicDashboardView()` guard. This exposes internal network topology (hostnames,
  ports, cloud endpoint URLs) for ALL direct-mode datasource types, not just the
  Prometheus-specific `directUrl` covered by M1.
- **Impact**: Internal network topology disclosure for all direct-mode datasources to
  unauthenticated public dashboard viewers.
- **Root Cause**: `pkg/api/frontendsettings.go:496–510` — raw URL set in DTO without
  public dashboard context check.
- **Parent Finding**: H3
- **Detailed Report**: archon/findings/M18-pubdash-direct-url-field-exposure/draft.md

---

### M19 — X-Grafana-User Spoofing via CallResource

- **Severity**: MEDIUM
- **PoC Status**: theoretical
- **Summary**: When `SendUserHeader=false`, `UserHeaderMiddleware` is absent from the
  plugin middleware chain. `ClearAuthHeadersMiddleware` does not include
  `X-Grafana-User` in its strip list. An authenticated attacker can inject an
  arbitrary `X-Grafana-User` value into a CallResource request; this header reaches
  plugin backend outgoing HTTP calls and can spoof identity on backends that use
  `X-Grafana-User` for access control or audit.
- **Impact**: Identity spoofing on plugin backends using `X-Grafana-User` for access
  control or audit logging when `SendUserHeader=false` is configured.
- **Root Cause**: `pkg/services/pluginsintegration/pluginsintegration.go:212–213` —
  `UserHeaderMiddleware` conditionally absent; `GetAuthHTTPHeaders()` omits
  `X-Grafana-User`.
- **Parent Finding**: H1
- **Detailed Report**: archon/findings/M19-xgrafana-user-spoofing-callresource/draft.md

---

### M20 — SetOp WITH RECURSIVE Walker Skip

- **Severity**: MEDIUM
- **PoC Status**: theoretical
- **Summary**: `SetOp.walkSubtree` only walks `Left` and `Right` child statements —
  it does NOT walk `node.With`. A `WITH RECURSIVE` CTE attached to a
  UNION/INTERSECT/EXCEPT statement (`SetOp`) is never visited by `sqlparser.Walk`,
  so `allowedNode` is never called for the `With` node. This is a second distinct
  bypass path: the original M9 finding has the `With` node visited but `Recursive`
  ignored; this variant has the `With` node never visited at all.
- **Impact**: Same DoS impact as M9 via UNION/INTERSECT/EXCEPT statements. A
  future patch addressing only M9 (checking `v.Recursive`) would not close this
  variant.
- **Root Cause**: `pkg/expr/sql/parser_allow.go:130–133` — SetOp handler; AST
  walker skips `node.With`.
- **Parent Finding**: M9
- **Detailed Report**: archon/findings/M20-setop-with-recursive-walker-skip/draft.md

---

### M21 — JSON_TABLE ColOpts Expr Bypass

- **Severity**: MEDIUM
- **PoC Status**: theoretical
- **Summary**: `JSONTableColDef.walkSubtree` does not walk `col.Opts`
  (`JSONTableColOpts`), and `JSONTableColOpts.walkSubtree` calls `Walk(visit)` with
  no arguments (making it a no-op). Arbitrary SQL expressions placed in the
  `DEFAULT <expr> ON EMPTY` and `DEFAULT <expr> ON ERROR` clauses of a
  `JSON_TABLE` column definition are never checked by `AllowQuery`.
- **Impact**: Arbitrary blocked expressions can be hidden inside `JSON_TABLE` column
  options without triggering the allowlist. May enable function calls or expression
  evaluations that the allowlist otherwise blocks.
- **Root Cause**: `pkg/expr/sql/parser_allow.go:124` — `*sqlparser.JSONTableColDef`
  allowed unconditionally; `walkSubtree` skips `col.Opts`.
- **Parent Finding**: M9
- **Detailed Report**: archon/findings/M21-jsontable-colopts-expr-bypass/draft.md

---

### M22 — SELECT Named Window Clause Not Walked

- **Severity**: MEDIUM
- **PoC Status**: theoretical
- **Summary**: `Select.walkSubtree` traverses 10 fields but excludes `node.Window`
  (the named WINDOW clause). Expressions in `SELECT ... WINDOW w AS (PARTITION BY
  ... ORDER BY ...)` definitions are never presented to `allowedNode`. Neither
  `Window` nor `*WindowDef` appear in `allowedNode`'s switch. Expressions in named
  window PARTITION BY / ORDER BY clauses are invisible to `AllowQuery`.
- **Impact**: Potentially allows expressions that the allowlist would otherwise block
  to execute via named window definitions.
- **Root Cause**: `pkg/expr/sql/parser_allow.go:127` — `*sqlparser.Select` allowed
  unconditionally; `Select.walkSubtree` skips `node.Window`.
- **Parent Finding**: M9
- **Detailed Report**: archon/findings/M22-select-window-clause-not-walked/draft.md

---

### M23 — Provisioning RemoveSecrets V1 Schema Gap

- **Severity**: MEDIUM
- **PoC Status**: theoretical
- **Summary**: `RemoveSecretsForContactPoint` at `contactpoints.go:661` and
  `EncryptReceiverConfigSettings` at `alertmanager_config.go:341` share the
  identical V1 schema hardcoding root cause as `crypto.go:88` (M15). On the write
  path (`POST`/`PUT /api/v1/provisioning/contact-points`), non-V1 secret fields are
  not extracted from `Settings` to `SecureSettings` and remain plaintext in the
  database. On the GET path, they are returned unredacted in API responses.
- **Impact**: Expands the M15 schema-evolution gap to the provisioning write and GET
  paths, forming a complete end-to-end plaintext exposure chain for non-V1 secret
  fields.
- **Root Cause**: `pkg/services/ngalert/provisioning/contactpoints.go:661` and
  `pkg/services/ngalert/notifier/alertmanager_config.go:341` — hardcoded `schema.V1`.
- **Parent Finding**: M15
- **Detailed Report**: archon/findings/M23-provisioning-encrypt-v1-schema-gap/draft.md

---

### M24 — Integration V1 Config Assignment Redact Bypass

- **Severity**: MEDIUM
- **PoC Status**: theoretical
- **Summary**: `PostableGrafanaReceiverToIntegration` at `compat.go:157` hard-assigns
  `schema.V1` as `Integration.Config`. This `Config` field is used by
  `Integration.Encrypt()`, `Integration.Redact()`, and `Integration.SecureFields()`
  to enumerate secret paths. All three call `GetSecretFieldsPaths()` on the V1
  config, so non-V1 secrets are never encrypted, never redacted, and never reported
  in the SecureFields map.
- **Impact**: Read-path counterpart of the M15 and M23 write-path gaps. Completes the
  end-to-end plaintext exposure chain through the provisioning GET endpoint.
- **Root Cause**: `pkg/services/ngalert/notifier/legacy_storage/compat.go:157` —
  `GetSchemaVersionForIntegration(integrationType, schema.V1)`.
- **Parent Finding**: M15
- **Detailed Report**: archon/findings/M24-integration-v1-config-assignment-redact-bypass/draft.md

---

### M25 — UpdateContactPoint V1 Redacted Sentinel Bypass

- **Severity**: MEDIUM
- **PoC Status**: theoretical
- **Summary**: `UpdateContactPoint` at `contactpoints.go:271` uses `schema.V1` to
  determine which settings fields bearing `"<redacted>"` should be restored from
  storage. For non-V1 secret fields, the `"<redacted>"` sentinel is not recognized;
  the literal string is stored in the database and returned in subsequent GET
  responses. This silently corrupts integration configuration without returning an
  error.
- **Impact**: Silent data corruption: non-V1 secret fields updated with the redacted
  sentinel value are permanently broken (stored as literal `"<redacted>"`). Third
  site where V1 schema hardcoding causes incorrect behavior.
- **Root Cause**: `pkg/services/ngalert/provisioning/contactpoints.go:271` —
  `GetSchemaVersionForIntegration(iType, schema.V1)` used for redacted-value
  detection.
- **Parent Finding**: M15
- **Detailed Report**: archon/findings/M25-update-contact-point-v1-redacted-bypass/draft.md

---

## Attack Pattern Analysis

The 32 confirmed findings cluster into eight systemic attack patterns. Addressing
the root cause of each pattern resolves multiple findings simultaneously.

### AP-002 — Public Dashboard Missing Context Guard (6 findings: H3, H4, H8, H9, M1, M16, M18)

The most prevalent pattern. Code paths that decrypt or expose sensitive datasource
fields in `pkg/api/frontendsettings.go` lack `IsPublicDashboardView()` guards in
the credential extraction and URL assignment blocks. The CVE-2026-27877 fix added
filtering at one point (which datasources appear) but left credential extraction
ungated. The `ByRef` fallback at `ds_lookup.go:129` independently defeats the
filter for three dashboard JSON locations (template variables, panel datasource,
query target datasource). A single fix — passing actual org datasources into
`CreateDatasourceLookup` and adding `!c.IsPublicDashboardView()` guards around
credential extraction — would close H3, H4, H8, H9, M16, and M18 simultaneously.

### AP-001 — Unsanitized Inbound Header Passthrough (3 findings: H1, M17, M19)

`GetAuthHTTPHeaders()` enumerates headers to strip on inbound requests but omits
`X-DS-Authorization` and `X-Grafana-User`. Two code paths pass inbound headers
verbatim to outbound backend requests: the datasource proxy director (`ds_proxy.go`)
and the CallResource plugin path (`plugin_resource.go`). Adding the missing headers
to `GetAuthHTTPHeaders()` resolves all three findings.

### AP-025 — SQL Allowlist AST Walker Gaps (4 findings: M9, M20, M21, M22)

The SQL expression allowlist in `parser_allow.go` checks node types but not all
scalar fields or sub-trees. Four independent bypass paths were found: `With.Recursive`
bool invisible to `allowedNode`; `SetOp.With` never walked by `walkSubtree`;
`JSONTableColDef.col.Opts` not walked; `Select.node.Window` not walked. Each
requires a targeted single-line or single-function fix, but all share the same
root cause: the allowlist design assumes the AST walker visits all relevant nodes,
which it does not for certain constructs.

### AP-045 — Hardcoded Schema Version in Secret Field Discovery (4 findings: M15, M23, M24, M25)

`GetSchemaVersionForIntegration` is called with a hardcoded `schema.V1` in five
locations across the alerting notification pipeline. This creates a systemic
schema-evolution trap: any secret field added to an integration schema after V1
will silently escape encryption, redaction, and secure-field reporting. The fix
requires replacing hardcoded `schema.V1` with the latest schema version (or a
dynamic lookup), then auditing all five call sites.

### AP-040 — Empty-List Equals Allow-All (1 finding: H6)

`isAllowedIP()` in the auth proxy client treats an empty `acceptedIPs` slice as
"allow all" rather than "deny all." This is an inverted default that becomes a
critical vulnerability the moment the feature is enabled. The fix is a one-line
inversion from `if len(c.acceptedIPs) == 0 { return true }` to
`if len(c.acceptedIPs) == 0 { return false }`.

### AP-020 — Admission Webhook Early-Return Bypass (2 findings: M5, M10)

Two `validateDelete` early-return conditions in `register.go` bypass the
provisioned-dashboard immutability check: the `isStandalone` flag (M5) and the
empty-name condition triggered by DeleteCollection requests (M10). Both require
explicit handling to maintain the security invariant in those code paths.

### AP-022 — Async Reconciler Revocation Delay (1 finding: M6)

The Zanzana reconciler default of 1 hour combined with the RBAC cache TTL creates
a 61-minute window where revoked permissions remain effective. Reducing the default
interval or adding an out-of-band invalidation mechanism would address this pattern.

### AP-024 / AP-023 — Single-Barrier SQL Defense Without Database Constraint (1 finding: M8)

The `temp_user` UPDATE query matches records by invite code without an `org_id`
constraint, relying solely on a handler-level check — the same structural pattern
that enabled CVE-2024-10452. Adding `AND org_id=?` to the SQL WHERE clause adds a
defense-in-depth layer.

---

## Prioritized Recommendations

### Priority 1 — Patch the Public Dashboard Credential Disclosure Chain (H3, H4, H8, H9, M16, M18)

A single targeted fix resolves the entire chain:

1. In `pkg/api/frontendsettings.go`, wrap lines 541–577 (the credential extraction
   block) with `if !c.IsPublicDashboardView() { ... }`. Also guard lines 557–565
   (DS_INFLUXDB_08 branch) and 496–510 (URL assignment for direct-mode).

2. In `pkg/api/frontendsettings.go:851–853`, replace `CreateDatasourceLookup` with
   an empty slice with a call that passes the actual org datasources, so `ByRef`
   resolves to real datasource records instead of returning attacker UIDs verbatim.

3. Add a regression test asserting that a public dashboard with template variables,
   panel datasource fields, and query target fields set to arbitrary UIDs does NOT
   cause those datasources to appear with credentials in the frontend settings
   response.

### Priority 2 — Fix Auth Proxy Insecure Default (H6)

Change `proxy.go:200–202` to `if len(c.acceptedIPs) == 0 { return false }`. Add a
startup warning when auth proxy is enabled with no allowlist configured. Update
documentation to emphasize that the allowlist must be explicitly set to the
reverse proxy's IP.

### Priority 3 — Fix SQL Expression Allowlist Gaps (M9, M20, M21, M22)

- `parser_allow.go:170`: Change `case *sqlparser.With: return` to
  `case *sqlparser.With: return !v.Recursive`.
- `parser_allow.go:130–133`: Explicitly handle `SetOp.With` in the SetOp case.
- `parser_allow.go:124`: Walk `JSONTableColDef.col.Opts.ValOnEmpty` and
  `ValOnError` explicitly.
- `parser_allow.go:127`: Walk `Select.Window` and add `*WindowDef` to the
  allowedNode switch.
- Add a recursion-depth limit in the SQL engine layer as defense in depth.

### Priority 4 — Fix Alerting Schema Version Hardcoding (M15, M23, M24, M25)

Replace all `schema.V1` literals in `GetSchemaVersionForIntegration` call sites with
the latest available schema version. Audit `crypto.go:88`, `contactpoints.go:661`,
`contactpoints.go:271`, `alertmanager_config.go:341`, and `compat.go:157`. Add CI
tests that verify new integration secret fields are encrypted and redacted in API
responses.

### Priority 5 — Strip Security-Sensitive Headers in Plugin Middleware (H1, M17, M19)

Add `X-DS-Authorization` and `X-Grafana-User` (the `proxyutil.UserHeaderName`
constant) to the `GetAuthHTTPHeaders()` return slice in
`pkg/services/contexthandler/contexthandler.go:220–244`. Verify that
`ClearAuthHeadersMiddleware` applies this list to both the datasource proxy and
CallResource paths.

### Priority 6 — Address Remaining MEDIUM Findings

In order of operational risk:
- M12 (LDAP enable hook) — add admin-imposed disable flag to `user` schema
- M6 (Zanzana reconciler) — reduce default reconciler interval; add invalidation API
- M7 (invite quota) — fix duplicate middleware: `quota(org.QuotaTargetSrv)`
- M8 (temp_user SQL) — add `AND org_id=?` to WHERE clause
- M5 / M10 (provisioning bypass) — handle standalone and DeleteCollection explicitly
  in `validateDelete`
- H7 / M13 / M14 (auth configuration gaps) — document deployment requirements;
  consider hardening defaults

---

## Conclusion

The grafana/grafana codebase demonstrates mature engineering practices with a
comprehensive RBAC model, SAST infrastructure, and an active security advisory
program. However, the audit revealed a systemic pattern of **defense-in-depth
failures** where security controls are applied at one layer but the same sensitive
operation is reachable via adjacent code paths without the same control.

The most consequential manifestation of this pattern is the public dashboard
credential disclosure chain (H3, H4, H8, H9): a CVE fix was applied at the list
level (which datasources appear) but not at the value level (what fields are
returned for those datasources), and the filter itself is structurally defeated by a
fallback in `ByRef`. This represents a second bypass of CVE-2026-27877 — the same
CVE patched earlier in 2026 — within the same component.

The SQL expression allowlist (M9, M20–M22) shows a similar pattern: the allowlist
correctly identifies safe node types but the AST walker does not visit all relevant
sub-trees, creating multiple independent bypass paths through the same enforcement
boundary.

The alerting schema hardcoding cluster (M15, M23–M25) is a future-proofing gap
rather than a present-day credential disclosure — but it will silently turn into an
active secret leak whenever a new integration adds a secret field at schema version
V2 or later.

Overall security posture is assessed as **moderate risk with two high-priority
remediation items** (the public dashboard credential chain and the auth proxy
default). The remaining MEDIUM cluster reflects systemic design issues that, while
individually bounded, benefit from a coordinated remediation pass rather than
piecemeal fixes.

---

## Appendix A — Methodology Detail

### Review Chambers

| Chamber | Threat Cluster | Findings Produced |
|---------|---------------|-------------------|
| Chamber 1 | Public Dashboards, Datasource Proxy | H1, H3, M1, M2, M3, M4 |
| Chamber 2 | Provisioning / Admission, SQL Expressions, Quotas, TempUser | M5, M6, M7, M8, M9, M10, M11 |
| Chamber 3 | Authentication (Proxy, JWT, LDAP, OAuth, Render) | H6, H7, M12, M13, M14, M15 |

**Total chambers spawned**: 3  
**Hypotheses generated**: 45  
**Hypotheses promoted to VALID**: 15  
**Hypotheses dropped (debate)**: 30  
**Phase 10 variant findings**: 13  
**Total attack patterns registered**: 13 (AP-001 through AP-045, non-sequential)

### Cold Verification (Phase 9)

| Finding | Result | Action |
|---------|--------|--------|
| H1 (xds-auth-header-injection) | CONFIRMED, severity downgraded | MEDIUM |
| H2 (pubdash-credential-exposure, cold-verify artifact) | DROPPED (duplicate of H3) | Excluded |
| H3 (pubdash-credential-exposure) | CONFIRMED HIGH | Kept |
| H4 (cve-2026-27877-bypass) | CONFIRMED HIGH | Kept |
| H5 (graceperiod-provisioning-bypass) | FALSE POSITIVE | Excluded |
| H6 (proxy-auth-empty-allowlist) | CONFIRMED, downgraded to MEDIUM | PoC executed; opt-in feature, non-default |
| H7 (extjwt-empty-audience) | CONFIRMED, severity downgraded | MEDIUM |

### Phase 10 Variant Analysis

| Parent | Variants Found | Pattern |
|--------|---------------|---------|
| H3 | M16, M18 | AP-002 |
| H4 | H8, H9 | AP-002 |
| H1 | M17, M19 | AP-001 |
| M9 | M20, M21, M22 | AP-025 |
| M15 | M23, M24, M25 | AP-045 |

---

## Appendix B — Tool Versions and Artifacts

| Tool | Version / Detail |
|------|-----------------|
| CodeQL | Go + JavaScript databases; custom query suites in `archon/codeql-queries/` |
| Semgrep Pro | Custom rules in `archon/semgrep-rules/`; results in `archon/semgrep-res/` |
| Go test runner | Used for M9 executed PoC (`pkg/expr/sql/m9_poc_test.go`) |
| Docker | grafana/grafana:latest (12.4.2) and grafana/grafana:11.4.0 for executed PoCs |
| Model | claude-sonnet-4-6[1m] |
| Grafana commit | bb41ac0c85d854e32cb19874fb4b3f17163179a8 (main, 2026-04-11) |

### Key Artifact Paths

| Artifact | Path |
|---------|------|
| Knowledge base | archon/knowledge-base-report.md |
| Advisory report | archon/advisory-report.md |
| Attack pattern registry | archon/attack-pattern-registry.json |
| SAST results | archon/sast-results.md |
| Consolidation manifest | archon/findings-draft/consolidation-manifest.json |
| Audit state | archon/audit-state.json |
| Finding directories | archon/findings/{ID}-{slug}/ |
| PoC scripts | archon/findings/H3-pubdash-credential-exposure/poc.sh |
| Real-environment evidence | archon/real-env-evidence/ |
| Chamber debate transcripts | archon/chamber-workspace/chamber-{1,2,3}/debate.md |
| Adversarial reviews | archon/adversarial-reviews/ |

---

## Appendix C — Excluded Findings

| ID | Slug | Reason |
|----|------|--------|
| H2 | pubdash-credential-exposure | Duplicate of H3 (cold-verify artifact; same vulnerability, same code path) |
| H5 | graceperiod-provisioning-bypass | FALSE POSITIVE — adversarial review (`archon/adversarial-reviews/graceperiod-provisioning-bypass-review.md`) determined the `GracePeriodSeconds=0` behavior is a deliberate Kubernetes API convention, not a bypass |

---

*End of report. For questions about individual findings, see the finding-specific
`report.md` or `draft.md` files in `archon/findings/`. For the complete advisory
history and threat model, see `archon/knowledge-base-report.md`.*
