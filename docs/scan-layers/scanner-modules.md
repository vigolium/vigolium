# Scanner Modules Reference

Vigolium ships with **210 scanner modules** — 127 active and 83 passive — covering the OWASP Top 10 and beyond.

## Severity Scale

`critical` > `high` > `medium` > `low` > `suspect` > `info`

## Confidence Scale

- **certain** — Definitively confirmed (payload executed, error matched)
- **firm** — Likely confirmed by behavioral analysis
- **tentative** — Possible but unconfirmed (heuristic-based)

---

## Active Modules (127)

Active modules send modified requests to detect vulnerabilities via fuzzing, injection, and behavioral analysis.

### XSS

| Module ID | Name | Description | Severity | Confidence | Tags |
|---|---|---|---|---|---|
| `active-xss-light-url-params` | XSS Light - URL Parameters | Reflected XSS in URL parameters with POST→GET conversion | High | Firm | `xss`, `injection` |
| `active-xss-light-path` | XSS Light - Path Injection | Reflected XSS via path manipulation (recursive, cut, append) | High | Firm | `xss`, `injection` |
| `active-xss-light-param-discovery` | XSS Light - Parameter Discovery | Reflected XSS via echo parameter discovery | High | Firm | `xss`, `injection` |

### SQL Injection

| Module ID | Name | Description | Severity | Confidence | Tags |
|---|---|---|---|---|---|
| `active-sqli-error-based` | SQLi Error Based | Error-based SQLi via database error messages (MySQL, PostgreSQL, MSSQL, Oracle, SQLite) | Critical | Certain | `sqli`, `injection` |
| `active-sqli-boolean-blind` | Blind SQL Injection (Boolean-Based) | Boolean-based blind SQLi via TRUE/FALSE payload pairs with triple verification | High | Certain | `sqli`, `injection` |

### NoSQL Injection

| Module ID | Name | Description | Severity | Confidence | Tags |
|---|---|---|---|---|---|
| `active-nosqli-error-based` | NoSQLi Error Based | NoSQL injection via error messages (MongoDB, CouchDB, Cassandra) | Critical | Certain | `nosqli`, `injection` |
| `active-nosqli-operator-injection` | NoSQL Operator Injection | MongoDB operator injection (`$ne`, `$gt`, `$regex`, `$where`) for auth bypass | High | Firm | `nosqli`, `injection` |

### Template Injection

| Module ID | Name | Description | Severity | Confidence | Tags |
|---|---|---|---|---|---|
| `active-reflected-ssti` | Reflected SSTI | SSTI via math expression evaluation (e.g., `{{7*7}}=49`) | High | Certain | `ssti`, `injection` |
| `active-ssti-detection` | SSTI Detection | Diff-based SSTI via Boolean Error-Based Blind technique | High | Certain | `ssti`, `injection` |
| `active-csti-detection` | Client-Side Template Injection | CSTI in AngularJS/Vue.js applications via literal reflection | High | Firm | `ssti`, `injection` |

### File Inclusion

| Module ID | Name | Description | Severity | Confidence | Tags |
|---|---|---|---|---|---|
| `active-lfi-generic` | LFI Generic | LFI via path traversal payloads; matches known OS file signatures | Critical | Certain | `lfi`, `injection` |
| `active-lfi-path-traversal` | LFI Path Traversal | Advanced LFI with null bytes, double encoding, Unicode bypass | High | Firm | `lfi`, `injection` |

### Code Execution & Injection

| Module ID | Name | Description | Severity | Confidence | Tags |
|---|---|---|---|---|---|
| `active-code-exec` | Code Execution (RCE) | OS command injection via time-based blind (sleep/delay measurement) | Critical | Certain | `rce`, `injection` |
| `active-crlf-injection` | CRLF Injection | CRLF injection in HTTP headers via CR/LF character sequences | Medium | Firm | `injection` |
| `active-xxe-generic` | XXE Generic | XML external entity injection in generic XML endpoints | Critical | Certain | `xxe`, `injection` |
| `active-insecure-deserialization` | Insecure Deserialization | Error-based detection for Java, PHP, Python, Ruby, and .NET deserialization | High | Firm | `injection` |
| `active-input-behavior-probe` | Input Behavior Probe | Behavior change detection via header, path, debug param, and char probing | Suspect | Tentative | `injection` |

### SSRF & Out-of-Band (OAST)

| Module ID | Name | Description | Severity | Confidence | Tags |
|---|---|---|---|---|---|
| `active-ssrf-detection` | SSRF Detection | SSRF via in-band probes (internal IPs, cloud metadata) with response differential | High | Firm | `ssrf`, `injection` |
| `active-oast-probe` | OAST Probe | Blind vulnerabilities (blind SSRF, blind XXE, blind RCE) via DNS/HTTP callbacks | High | Certain | `ssrf`, `injection` |
| `active-proxy-pingback` | Proxy Pingback | Open proxy/callback endpoints via OAST URL injection | High | Certain | `ssrf`, `injection` |

### Misconfiguration

| Module ID | Name | Description | Severity | Confidence | Tags |
|---|---|---|---|---|---|
| `active-cors-misconfiguration` | CORS Misconfiguration | Permissive CORS policies (reflected origins, null origin, wildcard+credentials) | Medium | Firm | `misconfiguration` |
| `active-spring-actuator-misconfig` | Spring Actuator Misconfiguration | Exposed Spring Boot actuator endpoints leaking env vars, health, config | High | Firm | `misconfiguration` |
| `active-host-header-injection` | Host Header Injection | Host header injection via value reflection (password reset/cache poisoning) | Medium | Firm | `misconfiguration` |
| `active-web-cache-poisoning` | Web Cache Poisoning | Cache poisoning via unkeyed header injection (X-Forwarded-Host, X-Forwarded-Scheme) | High | Firm | `misconfiguration` |

### Access Control

| Module ID | Name | Description | Severity | Confidence | Tags |
|---|---|---|---|---|---|
| `active-forbidden-bypass` | 403/401 Forbidden Bypass | Bypass via path manipulation, header injection, method tampering | Medium | Firm | `auth-bypass` |
| `active-http-method-tampering` | HTTP Method Tampering | Unexpectedly enabled HTTP methods (PUT, DELETE, PATCH) and overrides | Medium | Firm | `auth-bypass` |
| `active-csrf-verify` | CSRF Token Verification | Verifies CSRF token enforcement by removing, emptying, or randomizing tokens | High | Firm | `auth-bypass` |
| `active-idor-detection` | IDOR Detection | Missing authorization on object ID parameters via neighbor ID probing | High | Tentative | `auth-bypass` |
| `active-mass-assignment` | Mass Assignment | Mass assignment via injecting privilege keys into JSON APIs | High | Firm | `auth-bypass` |
| `active-open-redirect` | Open Redirect | Open redirect via injected external URL in Location/meta refresh | Medium | Firm | `auth-bypass` |

### Path Analysis

| Module ID | Name | Description | Severity | Confidence | Tags |
|---|---|---|---|---|---|
| `active-path-normalization` | Path Normalization | Path normalization vulnerabilities via traversal payloads against middleware/reverse proxy | High | Firm | `misconfiguration` |
| `active-nginx-off-by-slash` | Nginx Off-by-Slash | Nginx alias traversal via missing trailing slash | High | Tentative | `misconfiguration` |
| `active-nginx-path-escape` | Nginx Path Escape Detection | Diff-based detection for alias traversal, URL encoding bypass, semicolon injection | High | Firm | `misconfiguration` |

### Differential & Behavior Detection

| Module ID | Name | Description | Severity | Confidence | Tags |
|---|---|---|---|---|---|
| `active-smart-behavior-detection` | Smart Behavior Detection | Diff-based injection detection via true/false behavioral payload pairs | Suspect | Firm | `detection` |
| `active-suspect-transform` | Suspect Transform Detection | Expression evaluation, quote consumption, and unicode normalizations | Suspect | Firm | `detection` |
| `active-backslash-transformation` | Backslash Transformation | Escape sequence interpretation, backslash consumption, character handling | Suspect | Firm | `detection` |

### Prototype Pollution

| Module ID | Name | Description | Severity | Confidence | Tags |
|---|---|---|---|---|---|
| `active-prototype-pollution` | Prototype Pollution | Server-side prototype pollution via `__proto__` and `constructor.prototype` JSON injection | High | Firm | `javascript`, `injection` |
| `active-client-prototype-pollution` | Client-Side Prototype Pollution | Client-side prototype pollution via JavaScript static analysis (source + gadget patterns) | High | Firm | `javascript`, `injection` |

### Race Conditions

| Module ID | Name | Description | Severity | Confidence | Tags |
|---|---|---|---|---|---|
| `active-race-interference` | Race Interference Detection | Race conditions via parallel request analysis (input storage, cross-contamination, TOCTOU) | High | Firm | `injection` |

### XML, JWT & HTTP Protocol

| Module ID | Name | Description | Severity | Confidence | Tags |
|---|---|---|---|---|---|
| `active-xml-saml-security` | XML SAML Security | XXE and DTD injection in SAML XML processing | High | Firm | `injection` |
| `active-jwt-vulnerability` | JWT Vulnerability | JWT algorithm confusion (`none` algorithm, empty signature, RS256→HS256) | Critical | Certain | `injection` |
| `active-http-request-smuggling` | HTTP Request Smuggling | CL.TE and TE.CL desync via conflicting Content-Length and Transfer-Encoding | High | Firm | `injection` |

### API & Endpoint Security

| Module ID | Name | Description | Severity | Confidence | Tags |
|---|---|---|---|---|---|
| `active-graphql-scan` | GraphQL Security Scanner | GraphQL introspection, SQL injection, and query batching abuse | Medium | Certain | `api`, `injection` |
| `active-file-upload-scan` | File Upload Scanner | File upload bypass (extension, null byte, magic bytes, SVG XXE, HTML XSS) | High | Certain | `injection` |
| `active-default-credentials` | Default Credentials | Login endpoints tested with common credential pairs; CAPTCHA/lockout aware | High | Certain | `auth-bypass` |
| `active-sensitive-file-discovery` | Sensitive File Discovery | ~25 marker-based sensitive files and ~1,350 generic paths (.env, .git, logs) | Medium | Firm | `info-disclosure` |
| `active-jsonp-callback` | JSONP Callback Injection | JSONP endpoints via callback injection enabling cross-origin data theft | Medium | Firm | `injection` |

### Proxy & Utility

| Module ID | Name | Description | Severity | Confidence | Tags |
|---|---|---|---|---|---|
| `active-proxy` | Proxy | Replay all requests through configured proxy | Info | Firm | `utility`, `light` |
| `active-proxy-header-trust` | Proxy Header Trust | Cross-framework proxy header trust issues via X-Forwarded-* manipulation | High | Firm | `misconfiguration`, `moderate` |
| `active-api-rate-limit-bypass` | API Rate Limit Bypass | Rate limiting bypass via IP spoofing headers | Medium | Firm | `auth-bypass`, `moderate` |
| `active-websocket-security` | WebSocket Security | Insecure WebSocket upgrade policies and missing origin validation | High | Firm | `misconfiguration`, `light` |
| `active-swagger-disclose` | Swagger Disclosure | Exposed Swagger/OpenAPI documentation | Medium | Firm | `api`, `info-disclosure`, `light` |
| `active-backup-file-discovery` | Backup File Discovery | Exposed backup archives derived from hostname and year variants | High | Firm | `sensitive-file`, `moderate` |
| `active-angular-template-injection` | Angular Template Injection | Angular template injection via expression evaluation | High | Firm | `angular`, `injection`, `ssti` |

### SQL Injection (Time-Based)

| Module ID | Name | Description | Severity | Confidence | Tags |
|---|---|---|---|---|---|
| `active-sqli-time-based-header` | SQLi Time Based - Header | Time-based SQL injection in HTTP headers | Critical | Certain | `injection`, `sqli`, `heavy` |
| `active-sqli-time-based-params` | SQLi Time Based - Params | Time-based SQL injection in parameters | Critical | Certain | `injection`, `sqli`, `heavy` |
| `active-sqli-time-blind` | Blind SQL Injection (Time-Based) | Time-based blind SQL injection | High | Firm | `injection`, `sqli`, `heavy` |

### SSRF & SSTI (Blind)

| Module ID | Name | Description | Severity | Confidence | Tags |
|---|---|---|---|---|---|
| `active-ssrf-blind` | Blind SSRF Detection | Blind SSRF via OAST callbacks | High | Firm | `ssrf`, `injection`, `heavy` |
| `active-ssti-blind` | Blind SSTI | Blind SSTI via OAST callbacks and time-delay payloads | Critical | Firm | `injection`, `ssti`, `heavy` |

### Framework Security

#### Next.js

| Module ID | Name | Description | Severity | Confidence | Tags |
|---|---|---|---|---|---|
| `active-nextjs-data-leakage` | Next.js Data Route Leakage | Unauthorized access to `/_next/data/<buildId>/<path>.json` | High | Firm | `nextjs`, `javascript` |
| `active-nextjs-middleware-bypass` | Next.js Middleware Bypass | CVE-2025-29927 and path normalization bypasses | Critical | Firm | `nextjs`, `javascript` |
| `active-nextjs-image-ssrf` | Next.js Image Optimizer SSRF | SSRF via `/_next/image` with OAST and in-band probes | High | Firm | `nextjs`, `javascript` |
| `active-nextjs-draft-mode-exposure` | Next.js Draft Mode Exposure | Insecure or unprotected Draft/Preview Mode endpoints | High | Firm | `nextjs`, `javascript` |
| `nextjs-version-audit` | Next.js Version Audit | Fingerprints Next.js version and maps to known CVE advisories | High | Firm | `nextjs`, `javascript`, `fingerprint` |
| `active-js-devserver-exposure` | JS Dev Server Exposure | Exposed webpack HMR, Vite, Nuxt, Remix dev server endpoints | Medium | Firm | `javascript` |

#### Spring / Java

| Module ID | Name | Description | Severity | Confidence | Tags |
|---|---|---|---|---|---|
| `active-spring-actuator-misconfig` | Spring Actuator Misconfiguration | Exposed Spring Boot actuator endpoints | High | Firm | `spring`, `java` |
| `active-spring-boot-admin-exposure` | Spring Boot Admin Exposure | Exposed Spring Boot Admin dashboards | High | Firm | `spring`, `java` |
| `active-spring-cloud-config-exposure` | Spring Cloud Config Exposure | Exposed Config Server endpoints leaking secrets | Critical | Firm | `spring`, `java` |
| `active-spring-data-rest-exposure` | Spring Data REST Exposure | Auto-exposed repository endpoints with HAL/HATEOAS | Medium | Firm | `spring`, `java` |
| `active-spring-debug-exposure` | Spring Debug Exposure | Debug endpoints, Whitelabel errors, stack traces | Medium | Firm | `spring`, `java` |
| `active-spring-gateway-exposure` | Spring Gateway Exposure | Exposed Cloud Gateway actuator revealing routes | High | Firm | `spring`, `java` |
| `active-spring-h2-console-exposure` | Spring H2 Console Exposure | Exposed H2 database web consoles | Critical | Firm | `spring`, `java`, `rce` |
| `active-spring-jolokia-exposure` | Spring Jolokia Exposure | Exposed Jolokia JMX endpoints | High | Firm | `spring`, `java` |
| `active-java-appserver-console` | Java App Server Console | Exposed admin consoles (WildFly, WebLogic, GlassFish) | High | Firm | `java`, `tomcat` |
| `active-java-sensitive-files` | Java Sensitive Files | Java config files, WEB-INF, META-INF, build artifacts | High | Firm | `java`, `sensitive-file` |
| `active-tomcat-manager-exposure` | Tomcat Manager Exposure | Exposed Tomcat Manager and Host Manager interfaces | High | Firm | `tomcat`, `java` |

#### Django / Flask / FastAPI (Python)

| Module ID | Name | Description | Severity | Confidence | Tags |
|---|---|---|---|---|---|
| `django-admin-exposure` | Django Admin Exposure | Exposed Django admin panel and login page | Medium | Firm | `django`, `python` |
| `django-browsable-api-exposure` | Django Browsable API Exposure | DRF browsable API detected via Accept header | Low | Firm | `django`, `python` |
| `django-debug-exposure` | Django Debug Exposure | Django DEBUG=True information disclosure | High | Firm | `django`, `python` |
| `django-debug-toolbar-exposure` | Django Debug Toolbar Exposure | Exposed django-debug-toolbar panels | High | Firm | `django`, `python` |
| `flask-werkzeug-debugger` | Flask Werkzeug Debugger | Exposed Werkzeug interactive debugger (RCE) | Critical | Certain | `flask`, `python`, `rce` |
| `fastapi-docs-exposure` | FastAPI Docs Exposure | Exposed FastAPI interactive API documentation | Low | Firm | `fastapi`, `python` |
| `fastapi-auth-inconsistency` | FastAPI Auth Inconsistency | Unprotected operations found via OpenAPI schema | Medium | Firm | `fastapi`, `python` |

#### Laravel / Symfony / PHP

| Module ID | Name | Description | Severity | Confidence | Tags |
|---|---|---|---|---|---|
| `active-laravel-admin-exposure` | Laravel Admin Exposure | Exposed admin panels, API docs, GraphQL endpoints | High | Firm | `laravel`, `php` |
| `active-laravel-devtool-exposure` | Laravel Developer Tool Exposure | Exposed Web Tinker, Clockwork, Pulse, Log Viewer | High | Firm | `laravel`, `php` |
| `active-laravel-ignition-rce` | Laravel Ignition RCE | CVE-2021-3129 RCE via exposed Ignition endpoints | Critical | Firm | `laravel`, `php`, `rce` |
| `active-laravel-misconfig` | Laravel Misconfiguration | Debug mode, exposed debugbar, application logs | High | Firm | `laravel`, `php` |
| `active-laravel-sensitive-files` | Laravel Sensitive Files | PHPUnit config, SQLite DB, storage internals | High | Firm | `laravel`, `php` |
| `active-symfony-misconfig` | Symfony Misconfiguration | Exposed profiler, debug toolbar, dev front controller | High | Firm | `symfony`, `php` |
| `active-php-composer-exposure` | PHP Composer Exposure | Exposed Composer manifests, vendor directory | High | Firm | `php` |
| `active-php-debug-exposure` | PHP Debug Exposure | Exposed phpinfo, PHP-FPM status, phpMyAdmin | Medium | Firm | `php` |
| `active-php-framework-debug` | PHP Framework Debug Exposure | Debug endpoints for Yii, CodeIgniter, CakePHP | Medium | Firm | `php` |
| `active-php-path-info-misconfig` | PHP PATH_INFO Misconfiguration | cgi.fix_pathinfo routing ambiguity | Medium | Firm | `php` |
| `active-php-source-disclosure` | PHP Source Disclosure | PHP source code via .phps handlers | High | Firm | `php` |

#### Rails (Ruby)

| Module ID | Name | Description | Severity | Confidence | Tags |
|---|---|---|---|---|---|
| `active-rails-info-exposure` | Rails Info Exposure | Exposed Rails dev/debug endpoints in production | High | Firm | `rails`, `ruby` |
| `active-rails-admin-dashboard` | Rails Admin Dashboard | Exposed Rails ecosystem admin panels | High | Firm | `rails`, `ruby` |
| `active-rails-sensitive-files` | Rails Sensitive Files | Exposed Rails config, credentials, artifacts | Critical | Firm | `rails`, `ruby` |
| `active-rails-action-mailbox-probe` | Rails Action Mailbox Probe | Exposed Action Mailbox ingress endpoints | Medium | Firm | `rails`, `ruby` |
| `active-rails-active-storage-probe` | Rails Active Storage Probe | Exposed Active Storage direct upload endpoints | Medium | Firm | `rails`, `ruby` |

#### Express (Node.js)

| Module ID | Name | Description | Severity | Confidence | Tags |
|---|---|---|---|---|---|
| `active-express-debug-probe` | Express Debug Probe | Stack trace and debug info leakage | Low | Firm | `express`, `javascript` |
| `active-express-directory-listing` | Express Directory Listing | Directory listing via serve-index middleware | Low | Firm | `express`, `javascript` |
| `active-express-trust-proxy-misconfig` | Express Trust Proxy Misconfiguration | Trust proxy misconfiguration via X-Forwarded-* | Medium | Firm | `express`, `javascript` |

#### ASP.NET / IIS

| Module ID | Name | Description | Severity | Confidence | Tags |
|---|---|---|---|---|---|
| `active-aspnet-blazor-exposure` | ASP.NET Blazor Exposure | Exposed Blazor WebAssembly assemblies and Server endpoints | Medium | Firm | `aspnet` |
| `active-aspnet-health-exposure` | ASP.NET Health Endpoint Exposure | Exposed health checks, monitoring dashboards, metrics | Medium | Firm | `aspnet` |
| `active-aspnet-identity-probe` | ASP.NET Identity Probe | Exposed Identity endpoints and IdentityServer | Medium | Firm | `aspnet` |
| `active-aspnet-misconfig` | ASP.NET Misconfiguration | Exposed diagnostics, debug endpoints, verbose errors | High | Firm | `aspnet` |
| `active-aspnet-sensitive-files` | ASP.NET Sensitive Files | Exposed config files, backups, sensitive directories | High | Firm | `aspnet` |
| `active-aspnet-service-exposure` | ASP.NET Service Exposure | Exposed ASMX, WCF, OData, legacy service paths | Medium | Firm | `aspnet` |
| `active-aspnet-viewstate-scan` | ASP.NET ViewState Scan | ViewState MAC disabled, event validation bypass | High | Firm | `aspnet` |
| `active-iis-shortname-discovery` | IIS Short Filename Discovery | IIS 8.3 short filename enumeration via tilde oracle | Medium | Certain | `aspnet` |

#### Firebase

| Module ID | Name | Description | Severity | Confidence | Tags |
|---|---|---|---|---|---|
| `active-firebase-auth-misconfig` | Firebase Auth Misconfiguration | Firebase Authentication misconfigurations | Medium | Firm | `firebase` |
| `active-firebase-functions-exposure` | Firebase Functions Exposure | Unauthenticated Cloud Functions | High | Firm | `firebase` |
| `active-firebase-misconfig` | Firebase Misconfiguration | Exposed Firebase config, security rules, credentials | High | Firm | `firebase` |
| `active-firebase-rtdb-exposure` | Firebase RTDB Exposure | Publicly readable Realtime Database | Critical | Certain | `firebase` |
| `active-firebase-storage-exposure` | Firebase Storage Exposure | Publicly accessible Cloud Storage buckets | High | Certain | `firebase`, `cloud` |

#### Cloud Infrastructure

| Module ID | Name | Description | Severity | Confidence | Tags |
|---|---|---|---|---|---|
| `active-cloud-bucket-takeover` | Cloud Bucket Takeover | Dangling cloud storage buckets vulnerable to takeover | High | Firm | `cloud` |
| `active-cloud-origin-bypass` | Cloud Origin Bypass | Direct access to origins bypassing CDN security | Medium | Firm | `cloud` |
| `active-cloud-public-read` | Cloud Public Read | Publicly readable sensitive paths on cloud storage | High | Firm | `cloud` |
| `active-cloud-storage-listing` | Cloud Storage Listing | Publicly listable S3 buckets and Azure containers | High | Certain | `cloud` |

#### CMS (WordPress, Drupal, Joomla, Magento)

| Module ID | Name | Description | Severity | Confidence | Tags |
|---|---|---|---|---|---|
| `active-wp-misconfig` | WordPress Misconfiguration | Exposed config files, debug logs, dangerous endpoints | High | Firm | `wordpress`, `php` |
| `active-wp-user-enum` | WordPress User Enumeration | User enumeration via author archives and REST API | Medium | Certain | `wordpress`, `php` |
| `active-wp-xmlrpc` | WordPress XML-RPC Abuse | XML-RPC multicall brute-force and pingback abuse | Medium | Firm | `wordpress`, `php` |
| `active-wp-ajax-exposure` | WordPress AJAX Action Exposure | Publicly accessible AJAX actions from plugins | High | Firm | `wordpress`, `php` |
| `active-drupal-misconfig` | Drupal Misconfiguration | Exposed config files, update scripts, installer | High | Firm | `drupal`, `php` |
| `active-drupal-user-enum` | Drupal User Enumeration | User enumeration via user profiles and JSON:API | Medium | Certain | `drupal`, `php` |
| `active-joomla-misconfig` | Joomla Misconfiguration | Exposed config backups, log/temp dirs, debug settings | High | Firm | `joomla`, `php` |
| `active-joomla-user-enum` | Joomla User Enumeration | User enumeration via registration, API, admin login | Medium | Firm | `joomla`, `php` |
| `active-magento-misconfig` | Magento Misconfiguration | Exposed setup wizard, downloader, version files | High | Firm | `magento`, `php` |
| `active-cms-installer-exposure` | CMS Installer Exposure | Exposed WordPress, Drupal, and Joomla install wizards | Critical | Firm | `wordpress`, `drupal`, `joomla` |

---

## Passive Modules (83)

Passive modules analyze existing request/response pairs without sending new traffic.

### XSS

| Module ID | Name | Description | Severity | Confidence | Tags |
|---|---|---|---|---|---|
| `passive-dom-xss-detect` | DOM XSS Detect | DOM XSS source-to-sink data flows (location.hash, innerHTML, eval, document.write) | Medium | Firm | `xss` |

### Authentication & Session

| Module ID | Name | Description | Severity | Confidence | Tags |
|---|---|---|---|---|---|
| `passive-auth-headers-detect` | Auth Headers Detect | Authorization headers (Bearer tokens, API keys) in requests | High | Firm | `session`, `auth` |
| `passive-jwt-weak-secret` | JWT Weak Secret Detection | Offline brute-force of JWT HMAC secrets against ~104K wordlist | High | Firm | `session`, `auth` |
| `passive-cookie-security-detect` | Cookie Security Detect | Insecure cookie attributes (missing Secure, HttpOnly, SameSite) | Low | Certain | `session`, `auth` |
| `passive-cacheable-https-detect` | Cacheable HTTPS Response | Sensitive HTTPS responses without proper Cache-Control | Low | Firm | `session`, `auth` |
| `passive-password-autocomplete-detect` | Password Autocomplete | Password fields without `autocomplete="off"` | Info | Certain | `session`, `auth` |

### Injection Signals

| Module ID | Name | Description | Severity | Confidence | Tags |
|---|---|---|---|---|---|
| `passive-sql-syntax-detect` | SQL Syntax in Request | SQL statements/keywords in HTTP request parameter values | Info | Firm | `injection` |
| `passive-serialized-object-detect` | Serialized Object Detection | Serialized Java/PHP/.NET/Python objects in request parameters | Medium | Firm | `injection` |
| `passive-input-reflection-detect` | Input Reflection Detect | Request parameter values reflected verbatim in response bodies | Info | Tentative | `injection` |
| `passive-base64-data-detect` | Base64 Data Detect | Interesting base64 data (JSON, PHP objects, URLs, Java objects) in requests/responses | Info | Tentative | `injection` |

### Information Disclosure

| Module ID | Name | Description | Severity | Confidence | Tags |
|---|---|---|---|---|---|
| `passive-secret-detect` | Secret Detection | Leaked secrets, API keys, and credentials via Kingfisher engine | High | Firm | `info-disclosure` |
| `passive-info-disclosure-detect` | Info Disclosure Detect | Server versions, internal IPs, stack traces, debug information | Low | Firm | `info-disclosure` |
| `passive-error-message-detect` | Error Message Detect | Error messages from debug pages, Apache, ASP.NET, Java, PHP, Ruby, Node.js, SQL | Info | Firm | `info-disclosure` |
| `passive-sourcemap-detect` | Sourcemap Exposure | Exposed JavaScript sourcemaps via SourceMappingURL references | Low | Firm | `info-disclosure` |
| `passive-sensitive-url-params` | Sensitive URL Params | Passwords, tokens, API keys passed in URL query parameters | Medium | Firm | `info-disclosure` |
| `passive-content-type-mismatch` | Content Type Mismatch | Content-Type/body mismatches enabling MIME confusion attacks | Low | Firm | `info-disclosure` |

### Security Headers & Configuration

| Module ID | Name | Description | Severity | Confidence | Tags |
|---|---|---|---|---|---|
| `passive-security-headers-missing` | Security Headers Missing | Missing X-Content-Type-Options, X-Frame-Options, HSTS, CSP, Permissions-Policy | Info | Certain | `header-security` |
| `passive-mixed-content-detect` | Mixed Content Detect | HTTP resources loaded on HTTPS pages (src, href, action attributes) | Low | Certain | `header-security` |

### CORS & Redirect

| Module ID | Name | Description | Severity | Confidence | Tags |
|---|---|---|---|---|---|
| `passive-cors-headers-detect` | CORS Headers Detect | Permissive CORS headers (wildcard origin, credentials enabled) | Low | Firm | `cors` |
| `passive-openredirect-params` | Open Redirect Params | URL parameter names associated with open redirects (redirect, url, next, goto) | Info | Tentative | `cors` |
| `passive-oauth-facebook-detect` | Facebook OAuth Detect | Facebook OAuth redirect parameters for OAuth flow analysis | Medium | Firm | `cors` |

### Access Control

| Module ID | Name | Description | Severity | Confidence | Tags |
|---|---|---|---|---|---|
| `passive-csrf-detect` | CSRF Detection | State-changing requests (POST/PUT/DELETE/PATCH) missing anti-CSRF protections | Medium | Tentative | `auth-bypass` |
| `passive-idor-params-detect` | IDOR Parameter Detection | Parameters referencing object identifiers for IDOR/BOLA triage | Info | Tentative | `auth-bypass` |

### Cryptography

| Module ID | Name | Description | Severity | Confidence | Tags |
|---|---|---|---|---|---|
| `passive-crypto-weakness-detect` | Cryptographic Weakness | PHP magic hashes, weak MD5/SHA1, padding oracle errors, unprotected encrypted cookies | Medium | Tentative | `crypto` |

### Anomaly Detection

| Module ID | Name | Description | Severity | Confidence | Tags |
|---|---|---|---|---|---|
| `passive-anomaly-ranking` | Anomaly Ranking | Statistical anomaly detection across per-host response batches; updates risk_score | Suspect | Tentative | `detection` |

### JS Framework Security (Runtime Analysis)

| Module ID | Name | Description | Severity | Confidence | Tags |
|---|---|---|---|---|---|
| `passive-js-framework-fingerprint` | JS Framework Fingerprint | Identifies Next.js, Nuxt, Angular, React, Remix, SvelteKit, Gatsby; extracts buildId | Info | Certain | `javascript` |
| `passive-ssr-data-exposure` | SSR Data Exposure | Sensitive data in SSR state blobs (`__NEXT_DATA__`, `__NUXT__`, `__INITIAL_STATE__`) | Medium | Firm | `javascript` |
| `passive-cache-auth-misconfiguration` | Cache-Auth Misconfiguration | Cacheable responses with user-specific data missing Vary headers | Medium | Firm | `javascript` |
| `passive-server-action-auth` | Server Action Auth Check | Next.js Server Actions with mutation operations but no authorization | High | Tentative | `javascript` |
| `passive-nextjs-config-audit` | Next.js Config Audit | Insecure Next.js config (dangerouslyAllowSVG, wildcard image domains, prod sourcemaps) | Medium | Firm | `javascript` |
| `passive-client-auth-guard` | Client Auth Guard Check | Client-only auth guards (useEffect redirects) without server-side enforcement | High | Tentative | `javascript` |
| `passive-cache-data-leak` | Cache Data Leak | `getStaticProps`/force-static with auth, `unstable_cache` without user-scoped keys | Medium | Tentative | `javascript` |

### JS Framework Security (Source Analysis)

| Module ID | Name | Description | Severity | Confidence | Tags |
|---|---|---|---|---|---|
| `passive-unsafe-html-sink` | Unsafe HTML Sink | Raw HTML injection sinks: `dangerouslySetInnerHTML`, `v-html`, `{@html}`, `innerHTML` | High | Firm | `javascript` |
| `passive-insecure-token-storage` | Insecure Token Storage | Auth tokens stored in `localStorage`/`sessionStorage` | Medium | Firm | `javascript` |
| `passive-env-secret-exposure` | Environment Secret Exposure | Secrets in `NEXT_PUBLIC_`, `VITE_`, `REACT_APP_` public env vars; served `.env` files | High | Firm | `javascript` |
| `passive-build-misconfig-detect` | Build Misconfiguration | Prod sourcemaps, dev mode in production, SVG XSS risk, broad image `remotePatterns` | High | Firm | `javascript` |

### Framework Fingerprinting

| Module ID | Name | Description | Severity | Confidence | Tags |
|---|---|---|---|---|---|
| `passive-aspnet-fingerprint` | ASP.NET Fingerprint | Fingerprints ASP.NET version and configuration | Info | Firm | `aspnet`, `fingerprint` |
| `passive-aspnet-viewstate-detect` | ASP.NET ViewState Detect | Analyzes ViewState fields for security issues | Medium | Firm | `aspnet` |
| `passive-django-fingerprint` | Django Fingerprint | Fingerprints Django framework indicators | Info | Firm | `django`, `python`, `fingerprint` |
| `passive-express-fingerprint` | Express Fingerprint | Fingerprints Express.js indicators | Info | Firm | `express`, `fingerprint` |
| `passive-fastapi-fingerprint` | FastAPI Fingerprint | Fingerprints FastAPI framework indicators | Info | Firm | `fastapi`, `python`, `fingerprint` |
| `passive-firebase-fingerprint` | Firebase Fingerprint | Fingerprints Firebase SDK usage and config | Info | Firm | `firebase`, `fingerprint` |
| `passive-flask-fingerprint` | Flask Fingerprint | Fingerprints Flask framework indicators | Info | Firm | `flask`, `python`, `fingerprint` |
| `passive-laravel-fingerprint` | Laravel Fingerprint | Fingerprints Laravel framework indicators | Info | Firm | `laravel`, `php`, `fingerprint` |
| `passive-rails-fingerprint` | Rails Fingerprint | Fingerprints Rails framework indicators | Info | Firm | `rails`, `ruby`, `fingerprint` |
| `passive-spring-fingerprint` | Spring Fingerprint | Fingerprints Spring Boot indicators | Info | Firm | `spring`, `java`, `fingerprint` |
| `passive-drupal-fingerprint` | Drupal Fingerprint | Fingerprints Drupal CMS indicators | Info | Firm | `drupal`, `php`, `fingerprint` |
| `passive-joomla-fingerprint` | Joomla Fingerprint | Fingerprints Joomla CMS indicators | Info | Firm | `joomla`, `php`, `fingerprint` |
| `passive-wp-fingerprint` | WordPress Fingerprint | Fingerprints WordPress CMS indicators | Info | Firm | `wordpress`, `php`, `fingerprint` |

### API & Protocol Analysis

| Module ID | Name | Description | Severity | Confidence | Tags |
|---|---|---|---|---|---|
| `passive-api-version-detect` | API Version Detection | Detects API versioning patterns in URLs and headers | Info | Firm | `api` |
| `passive-graphql-introspection-detect` | GraphQL Introspection Detect | Detects enabled GraphQL introspection | Medium | Certain | `api`, `graphql` |
| `passive-grpc-web-detect` | gRPC-Web Detect | Detects gRPC-Web traffic patterns | Info | Firm | `api` |
| `passive-endpoint-classifier` | Endpoint Classifier | Classifies endpoint types (API, auth, admin, static) | Info | Tentative | `api` |

### Security Headers & Policy

| Module ID | Name | Description | Severity | Confidence | Tags |
|---|---|---|---|---|---|
| `passive-csp-weakness-audit` | CSP Weakness Audit | Content-Security-Policy weaknesses and bypasses | Medium | Firm | `header-security` |
| `passive-permissions-policy-detect` | Permissions-Policy Detect | Missing or weak Permissions-Policy/Feature-Policy | Info | Certain | `header-security` |
| `passive-hsts-preload-audit` | HSTS Preload Audit | HSTS header configuration and preload readiness | Info | Firm | `header-security` |
| `passive-referrer-policy-detect` | Referrer-Policy Detect | Missing or weak Referrer-Policy | Info | Firm | `header-security` |
| `passive-subresource-integrity-detect` | Subresource Integrity Detect | Scripts/styles loaded without SRI attributes | Low | Firm | `header-security` |
| `passive-cors-vary-origin-missing` | CORS Vary: Origin Missing | CORS responses without Vary: Origin header | Low | Firm | `cors`, `header-security` |

### Cloud & Firebase

| Module ID | Name | Description | Severity | Confidence | Tags |
|---|---|---|---|---|---|
| `passive-cloud-storage-fingerprint` | Cloud Storage Fingerprint | Identifies cloud storage provider from URLs/headers | Info | Firm | `cloud`, `fingerprint` |
| `passive-cloud-storage-error-info` | Cloud Storage Error Info | Cloud storage error messages revealing bucket names | Low | Firm | `cloud`, `info-disclosure` |
| `passive-cloud-signed-url-leak` | Cloud Signed URL Leak | Cloud signed URLs with excessive permissions or long expiry | Medium | Firm | `cloud`, `info-disclosure` |

### CMS Detection

| Module ID | Name | Description | Severity | Confidence | Tags |
|---|---|---|---|---|---|
| `passive-drupal-api-detect` | Drupal API Detect | Detects Drupal JSON:API and REST endpoints | Info | Firm | `drupal`, `api` |
| `passive-joomla-api-detect` | Joomla API Detect | Detects Joomla API endpoints and versions | Info | Firm | `joomla`, `api` |
| `passive-wp-rest-api-detect` | WordPress REST API Detect | Detects WordPress REST API endpoints | Info | Firm | `wordpress`, `api` |

### Advanced JS Framework Analysis

| Module ID | Name | Description | Severity | Confidence | Tags |
|---|---|---|---|---|---|
| `passive-nextjs-dynamic-param-audit` | Next.js Dynamic Param Audit | Audits Next.js dynamic route parameters for injection | Medium | Tentative | `nextjs`, `javascript` |
| `passive-nextauth-config-audit` | NextAuth.js Config Audit | Audits NextAuth.js configuration for security issues | Medium | Firm | `nextjs`, `javascript` |
| `passive-nuxt-config-audit` | Nuxt Config Audit | Audits Nuxt.js configuration for security issues | Medium | Firm | `nuxt`, `javascript` |
| `passive-remix-loader-exposure` | Remix Loader Exposure | Detects exposed Remix loader data | Medium | Firm | `remix`, `javascript` |
| `passive-ssr-hydration-xss` | SSR Hydration XSS | Detects XSS via SSR hydration mismatches | High | Firm | `javascript`, `xss` |
| `passive-server-action-bind-audit` | Server Action Bind Audit | Audits Next.js Server Action .bind() usage for security | Medium | Tentative | `nextjs`, `javascript` |
| `passive-server-action-input-audit` | Server Action Input Audit | Audits Next.js Server Action input validation | Medium | Tentative | `nextjs`, `javascript` |
| `passive-server-only-boundary-audit` | Server-Only Boundary Audit | Audits server-only module boundary enforcement | Medium | Tentative | `nextjs`, `javascript` |
| `passive-javascript-uri-sink` | JavaScript URI Sink | Detects javascript: URI usage in links and event handlers | High | Firm | `javascript`, `xss` |
| `passive-wasm-module-detect` | WebAssembly Module Detect | Detects WebAssembly module loading | Info | Firm | `javascript` |

### Session & Authentication (Passive)

| Module ID | Name | Description | Severity | Confidence | Tags |
|---|---|---|---|---|---|
| `passive-express-session-audit` | Express Session Audit | Audits Express session cookie configuration | Medium | Firm | `express`, `session` |
| `passive-jwt-claims-detect` | JWT Claims Detect | Analyzes JWT payload claims for security issues | Info | Firm | `auth`, `session` |
| `passive-jackson-deserialize-detect` | Jackson Deserialization Detect | Detects Jackson default typing indicators | Medium | Firm | `java`, `injection` |
| `passive-python-debug-detect` | Python Debug Detect | Detects Python debug/traceback indicators | Low | Firm | `python` |
| `passive-rails-debug-detect` | Rails Debug Detect | Detects Rails debug page indicators | Medium | Firm | `rails`, `ruby` |
| `passive-rails-action-cable-detect` | Rails Action Cable Detect | Detects Rails Action Cable WebSocket endpoints | Info | Firm | `rails`, `ruby` |
| `passive-rails-active-storage-detect` | Rails Active Storage Detect | Detects Active Storage blob URLs and signed tokens | Info | Firm | `rails`, `ruby` |
| `passive-sensitive-api-fields-detect` | Sensitive API Fields Detect | Detects sensitive field names in API responses | Medium | Tentative | `api`, `info-disclosure` |
