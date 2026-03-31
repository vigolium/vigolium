Phase: 10
Sequence: 003
Slug: kraken-preheat-no-url-revalidation
Verdict: VALID
Rationale: KrakenDriver.Preheat() and KrakenDriver.GetHealth() (and dragonfly's CheckProgress) use the stored instance Endpoint directly in HTTP requests without re-calling ValidateHTTPURL, meaning the Preheat and CheckProgress execution paths lack even the scheme-only check present in GetHealth, and none of these paths perform IP filtering.
Severity-Original: MEDIUM
PoC-Status: pending
Origin-Finding: security/findings-draft/p8-024-preheat-ssrf.md
Origin-Pattern: AP-022

## Summary

The preheat finding (p8-024) documented SSRF through `GetHealth` for Dragonfly and Kraken providers. A structural variant exists in the `Preheat()` and `CheckProgress()` methods of both providers: these execution paths use `kd.instance.Endpoint` directly to construct URLs and make HTTP requests without calling `ValidateHTTPURL` at all, even for the scheme check. The Kraken `GetHealth` calls `ValidateHTTPURL` at line 63, but `Preheat()` at line 89 constructs the URL from the same endpoint without validation before calling `client.GetHTTPClient(...).Post(url, ...)`. Dragonfly `Preheat()` at line 268 and `CheckProgress()` at line 297 also skip URL re-validation.

Since the endpoint originates from the stored preheat instance (user-controlled, confirmed in p8-024), the Preheat execution path represents an independent SSRF trigger that fires during artifact push events — increasing the attack surface and triggering frequency compared to the health-check-only path.

## Location

- `src/pkg/p2p/preheat/provider/kraken.go:89-108` — `Preheat()` constructs URL from `kd.instance.Endpoint`, no `ValidateHTTPURL`, HTTP POST made
- `src/pkg/p2p/preheat/provider/dragonfly.go:268-269` — `Preheat()` constructs URL from `dd.instance.Endpoint`, no `ValidateHTTPURL`, HTTP POST
- `src/pkg/p2p/preheat/provider/dragonfly.go:297-298` — `CheckProgress()` constructs URL, no `ValidateHTTPURL`, HTTP GET
- `src/controller/p2p/preheat/controller.go:195` — `CreateInstance` stores endpoint without validation (confirmed p8-024)

## Attacker Control

- System admin creates preheat instance with malicious endpoint via `POST /api/v2.0/p2p/preheat/instances`
- Endpoint stored in DB as confirmed in p8-024
- `Preheat()` triggered automatically on artifact push matching preheat policy — no further admin action needed
- `kd.instance.Insecure = true` disables TLS verification

## Trust Boundary Crossed

- TB-8: Job Service / Core container to internal network
- Automatic trigger on artifact push eliminates the need for manual health-check initiation

## Impact

- Same as p8-024: cloud metadata credential theft, internal service discovery
- Additional trigger vector: Preheat fires on every artifact push matching the policy, enabling high-frequency probing
- No scheme validation in Preheat path — technically allows non-http schemes if instance endpoint was stored with ftp:// or other scheme (CreateInstance only warns health check, doesn't validate endpoint format rigorously)

## Evidence

- `kraken.go:63`: `url, err := lib.ValidateHTTPURL(url)` present in `GetHealth()` only
- `kraken.go:89`: `url := fmt.Sprintf("%s%s", strings.TrimSuffix(kd.instance.Endpoint, "/"), krakenPreheatPath)` — no ValidateHTTPURL before HTTP call
- `dragonfly.go:268`: same pattern in `Preheat()` — no revalidation
- `dragonfly.go:297`: same in `CheckProgress()`
- Instance endpoint user-controlled per p8-024 evidence

## Reproduction Steps

1. Authenticate as system administrator
2. Create preheat instance: `POST /api/v2.0/p2p/preheat/instances` with `{"endpoint": "http://169.254.169.254/", "vendor": "kraken", "name": "test", "insecure": true}`
3. Create preheat policy for a project targeting this instance
4. Push any artifact matching the policy filter
5. `KrakenDriver.Preheat()` executes HTTP POST to `http://169.254.169.254/registry/notifications` — bypasses even scheme check in execution path
