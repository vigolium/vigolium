# Third Party Notices

This file acknowledges third-party projects, tools, datasets, reference
material, and embedded components that are used by or referenced from
Vigolium.

Each entry describes the specific role the project or resource serves in
Vigolium. This notice supplements the licenses and copyright notices included
with individual dependencies and does not replace the complete dependency
license inventory for transitive packages, generated assets, or bundled
binaries.

Vigolium itself is licensed under the GNU AGPL-3.0 (see `LICENSE` and
`NOTICE`). External engines and template sets such as Semgrep, GitHub CodeQL,
and the ProjectDiscovery nuclei-templates are invoked at runtime as
user-supplied tools — they are not redistributed as part of Vigolium and
remain under their own respective licenses. The AGPL terms apply to
Vigolium's own source code, not to these independently obtained tools.

## Source-Derived Code And Fixtures

| Project or source | Function in Vigolium |
| --- | --- |
| [go-shiori/dom](https://github.com/go-shiori/dom) | DOM query, traversal, mutation, and HTML helper behavior used by `pkg/anomaly/htmlutils` for response HTML analysis. |
| Go standard library `net/http/cookiejar` helpers | Cookie domain, path, and response-chain normalization helpers in `pkg/deparos/responsechain`. |

## Embedded Binaries And Companion Projects

| Project or source | Function in Vigolium |
| --- | --- |
| Chromium snapshots | Optional embedded Chromium browser archive for Spitolas browser automation builds. |
| [ungoogled-chromium portablelinux](https://github.com/ungoogled-software/ungoogled-chromium-portablelinux) | Optional embedded Linux browser engine for Spitolas. |
| [fingerprint-chromium](https://github.com/adryfish/fingerprint-chromium) | Optional embedded browser engine for fingerprint-aware Spitolas scans. |
| [vigolium/burp-vigolium](https://github.com/vigolium/burp-vigolium) | Burp Suite extension for forwarding live Burp traffic into a running Vigolium server for ingestion and scanning. |

## Scanning Engines And External Tools

| Project or source | Function in Vigolium |
| --- | --- |
| [ProjectDiscovery Nuclei](https://github.com/projectdiscovery/nuclei) | Known-issue scanner engine invoked through the Nuclei Go SDK. |
| [ProjectDiscovery nuclei-templates](https://github.com/projectdiscovery/nuclei-templates) | CVE, exposure, and misconfiguration templates downloaded or installed for known-issue scans. |
| [ProjectDiscovery interactsh](https://github.com/projectdiscovery/interactsh) | OAST callback correlation for blind vulnerability testing. |
| [ProjectDiscovery retryablehttp-go](https://github.com/projectdiscovery/retryablehttp-go) | Retrying HTTP client behavior used by scanner/network tooling. |
| [ProjectDiscovery rawhttp](https://github.com/projectdiscovery/rawhttp) | Raw HTTP request handling for lower-level scanner requests. |
| [MongoDB Kingfisher](https://github.com/mongodb/kingfisher) | Secret and credential detection engine for passive response scanning and Deparos batch secret detection. |
| [Semgrep](https://github.com/semgrep/semgrep) | Optional SAST engine invoked by vigolium-audit agents. |
| [GitHub CodeQL](https://github.com/github/codeql) | Optional static-analysis engine invoked by vigolium-audit agents. |

## Wordlists, Payload Lists, And Detection Patterns

| Project or source | Function in Vigolium |
| --- | --- |
| [Bo0oM/fuzz.txt](https://github.com/Bo0oM/fuzz.txt) | Likely source for `internal/resources/wordlists/fuzz.txt`, used for malformed path and discovery fuzzing. Verify provenance before release. |
| [wallarm/jwt-secrets](https://github.com/wallarm/jwt-secrets) | Likely source family for `internal/resources/wordlists/jwt.secrets.list`, used for weak JWT secret detection. Verify provenance before release. |
| `dir-short.txt`, `dir-long.txt`, `file-short.txt`, `file-long.txt` | Embedded content-discovery wordlists used by Deparos. Source provenance is not documented in-tree and should be verified before release. |
| [GerbenJavado/LinkFinder](https://github.com/GerbenJavado/LinkFinder) | LinkFinder-style JavaScript URL and endpoint extraction patterns in `pkg/deparos/jsscan/linkfinder`. |
| [PortSwigger Web Security Academy and Research](https://portswigger.net/web-security) | Vulnerability technique references, module references, payload inspiration, and scanner behavior references across active/passive modules. |
| [PortSwigger error-message-checks](https://github.com/PortSwigger/error-message-checks) | Error-message detection reference patterns for passive information-disclosure checks. |
| [Bugcrowd HUNT](https://github.com/bugcrowd/HUNT) | Interesting-parameter reference source for the `interesting_params.js` extension. |
| [1ndianl33t/Gf-Patterns](https://github.com/1ndianl33t/Gf-Patterns) | Interesting-parameter and error-pattern reference source for passive detections and extensions. |
| [tomnomnom/gf examples](https://github.com/tomnomnom/gf) | Base64 and pattern-detection reference material for passive data discovery. |
| [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) | Payload and technique references for file inclusion/path traversal and NoSQL injection modules. |
| [dalfox](https://github.com/hahwul/dalfox) | XSS WAF-evasion and encoding payload technique references for the `xssencode` mutators/encoding ladder and WAF-aware XSS modules. |
| [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/) | Security guidance references for extensions and module remediation text. |

## Agentic Audit And Prompt Resources

| Project or source | Function in Vigolium |
| --- | --- |
| [vigolium/piolium](https://github.com/vigolium/piolium) | Pi-native source-code security audit agent driving `vigolium agent audit --driver=piolium`. An extension of [Pi](https://github.com/earendil-works/pi). |
| [earendil-works/pi](https://github.com/earendil-works/pi) | Upstream Pi agent runtime that piolium extends. |
| [vigolium/vigolium-audit](https://github.com/vigolium/vigolium-audit) | Audit harness driving `vigolium agent audit` for source-code security audits. |
| [vercel-labs/agent-browser](https://github.com/vercel-labs/agent-browser) | Planning/reference material for browser-agent integration docs. |

## Benchmarks, Test Targets, And External Services

| Project or source | Function in Vigolium |
| --- | --- |
| [OWASP Juice Shop](https://github.com/juice-shop/juice-shop) | Canary and benchmark vulnerable application target. |
| [DVWA](https://github.com/digininja/DVWA) | Canary and benchmark vulnerable application target. |
| [VAmPI](https://github.com/erev0s/VAmPI) | Canary and benchmark vulnerable API target. |
| [crAPI](https://github.com/OWASP/crAPI) | Benchmark vulnerable API target. |
| [DataDog vulnerable Java application](https://github.com/DataDog/security-labs-pocs) | Benchmark vulnerable Java target referenced by test workflows/docs. |
| [Detectify vulnerable-nginx](https://github.com/detectify/vulnerable-nginx) | Benchmark vulnerable Nginx target. |
| OopsSec and Next.js vulnerable examples | SAST benchmark source fixtures and route-extraction tests. Verify fixture provenance if copied into the repository. |
| XBOW / Anthropic validation benchmarks | Benchmark reference material for agent evaluation docs/tests. |
| [PortSwigger ginandjuice.shop](https://ginandjuice.shop/) | External blackbox benchmark target referenced in benchmark docs. |
| [Internet Archive Wayback Machine](https://archive.org/web/) | URL harvesting source for historical URLs. |
| [Common Crawl](https://commoncrawl.org/) | URL harvesting source via CDX indices. |
| [AlienVault OTX](https://otx.alienvault.com/) | URL harvesting source via OTX domain URL API. |
| [urlscan.io](https://urlscan.io/) | URL harvesting source via urlscan search API. |
| [VirusTotal](https://www.virustotal.com/) | URL harvesting source via VirusTotal domain report API. |
