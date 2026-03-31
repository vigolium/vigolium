## CROSS-01: Pagination next_url host pivot (JSON URL runner)

Source-A: PH-02 from backward-reasoner (round-1-hypotheses.md)
Source-B: PH-01 from contradiction-reasoner (round-2-hypotheses.md)
Connection: Both target `redash/query_runner/json_ds.py` pagination path and rely on response-controlled `next_url` to pivot to internal hosts.
Combined hypothesis: Response-controlled pagination in JSON runner allows attacker to steer follow-on requests to internal hosts despite an initial benign URL.
Test direction for causal-verifier: Check whether `UrlPagination.next` accepts absolute URLs and whether `urljoin` preserves host changes; verify any allowlist or validation before `get_response`.

## CROSS-02: SSRF guard is config-gated (BaseHTTPQueryRunner)

Source-A: PH-01 from backward-reasoner (round-1-hypotheses.md)
Source-B: PH-02 from contradiction-reasoner (round-2-hypotheses.md)
Connection: Both depend on `ENFORCE_PRIVATE_ADDRESS_BLOCK` gating `requests_or_advocate` and allow SSRF when disabled.
Combined hypothesis: Private-address blocking is a soft control; disabling the setting fully restores SSRF capability across JSON/URL runners.
Test direction for causal-verifier: Confirm that `requests_or_advocate` becomes raw `requests` when setting is off and no other guard exists in query runners.

## CROSS-03: Redirect policy mismatch in CSV/Excel

Source-A: PH-03 from backward-reasoner (round-1-hypotheses.md)
Source-B: PH-03 from contradiction-reasoner (round-2-hypotheses.md)
Connection: Both target CSV/Excel paths using `requests_or_advocate.get` directly, bypassing `ConfiguredSession` redirect policy.
Combined hypothesis: CSV/Excel runners may follow redirects to internal addresses even when global redirect policy is disabled.
Test direction for causal-verifier: Compare redirect handling in `requests_or_advocate.get` vs `ConfiguredSession.request` when `REQUESTS_ALLOW_REDIRECTS` is false.

## CROSS-04: Absolute URL overrides base_url (JSON runner)

Source-A: PH-02 from backward-reasoner (round-1-hypotheses.md)
Source-B: PH-04 from contradiction-reasoner (round-2-hypotheses.md)
Connection: Both involve JSON runner URL handling and host pivoting; response-driven next_url and absolute URL in query both allow host override beyond base_url.
Combined hypothesis: JSON runner allows host escape either via absolute query URL or via response-controlled pagination, bypassing any intended base_url scoping.
Test direction for causal-verifier: Check whether absolute URLs or pagination URLs bypass base_url constraints and whether any upstream validation forbids absolute URLs.
