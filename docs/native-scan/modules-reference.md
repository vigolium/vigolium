# Scanner Modules Reference

Vigolium ships with **317 scanner modules** — 201 active and 116 passive — covering the OWASP Top 10 and beyond. The categorized tables below are a curated selection synchronized with the current registry. Run `vigolium module ls` (or call `GET /api/modules`) for all modules and the authoritative live metadata.

## Severity Scale

`critical` > `high` > `medium` > `low` > `suspect` > `info`

## Confidence Scale

- **certain** — Definitively confirmed (payload executed, error matched)
- **firm** — Likely confirmed by behavioral analysis
- **tentative** — Possible but unconfirmed (heuristic-based)

## Result Kinds and Evidence Grades

Security-relevant patterns are retained even when they do not yet prove a vulnerability. Each result has a kind and an evidence grade:

| Kind | Grade | Meaning |
|---|---|---|
| `observation` | `E0` | A feature, primitive, public identifier, or hardening gap exists. |
| `candidate` | `E1`–`E3` | Controls or a behavioral differential support an exploit hypothesis, but impact is not proven. |
| `finding` | usually `E4` | Unauthorized access, execution, durable state change, cross-user replay, or equivalent impact is demonstrated. |

Legacy modules that do not set a kind remain findings for compatibility. Candidate and observation records are stored and queryable with `vigolium finding --record-kind candidate,observation`, but they do not increase confirmed-finding totals or suppress another module from performing confirmation.

---

## Selected Active Modules

Active modules send modified requests to detect vulnerabilities via fuzzing, injection, and behavioral analysis.

### XSS

| Module ID | Name | Description | Severity | Confidence | Tags |
|---|---|---|---|---|---|
| `xss-light-url-params` | XSS Light - URL Parameters | Detects XSS in URL parameters (POST→GET conversion when applicable) | High | Firm | `injection`, `xss`, `light` |
| `xss-light-path` | XSS Light - Path Injection | Detects XSS via path manipulation (recursive, cut, append) | High | Firm | `injection`, `xss`, `light` |
| `xss-light-param-discovery` | XSS Light - Parameter Discovery | Detects XSS via echo parameter discovery | High | Firm | `injection`, `xss`, `light` |

### SQL Injection

| Module ID | Name | Description | Severity | Confidence | Tags |
|---|---|---|---|---|---|
| `sqli-error-based` | SQLi Error Based | Detects SQLi via error messages | Critical | Certain | `injection`, `sqli`, `moderate` |
| `sqli-boolean-blind` | Blind SQL Injection (Boolean-Based) | Detects boolean-based blind SQL injection vulnerabilities | High | Certain | `injection`, `sqli`, `heavy` |

### NoSQL Injection

| Module ID | Name | Description | Severity | Confidence | Tags |
|---|---|---|---|---|---|
| `nosqli-error-based` | NoSQLi Error Based | Detects NoSQL injection via error messages and operator injection | High | Tentative | `injection`, `sqli`, `moderate` |
| `nosqli-operator-injection` | NoSQL Operator Injection | Detects MongoDB operator injection ($ne, $gt, $regex, $where) for auth bypass and data exfiltration | High | Tentative | `injection`, `sqli`, `moderate` |

### Template Injection

| Module ID | Name | Description | Severity | Confidence | Tags |
|---|---|---|---|---|---|
| `reflected-ssti` | Reflected SSTI | Detects SSTI via math expression evaluation | High | Certain | `injection`, `ssti`, `moderate` |
| `ssti-detection` | SSTI Detection | Diff-based SSTI detection via error responses | Info | Certain | `injection`, `ssti`, `moderate` |
| `csti-detection` | Client-Side Template Injection (CSTI) | Detects client-side template injection in AngularJS/Vue.js applications | Medium | Firm | `angular`, `xss`, `injection`, `ssti`, `moderate` |

### File Inclusion

| Module ID | Name | Description | Severity | Confidence | Tags |
|---|---|---|---|---|---|
| `lfi-generic` | LFI Generic | Detects LFI via path traversal payloads | Critical | Certain | `lfi`, `injection`, `moderate` |
| `lfi-path-traversal` | LFI Path Traversal | Detects LFI via advanced path traversal, null bytes, encoding bypass, and multi-marker confirmation | High | Firm | `lfi`, `injection`, `heavy` |

### Code Execution & Injection

| Module ID | Name | Description | Severity | Confidence | Tags |
|---|---|---|---|---|---|
| `code-exec` | Code Execution (RCE) | Detects OS command injection via time-based blind | Critical | Certain | `rce`, `injection`, `heavy` |
| `command-injection-echo` | OS Command Injection (Results-Based) | Detects OS command injection by making the shell compute a unique arithmetic value echoed back in the response | Critical | Certain | `rce`, `command-injection`, `injection`, `moderate` |
| `command-injection-oast` | OS Command Injection (Out-of-Band) | Detects blind OS command injection via out-of-band DNS/HTTP callbacks | Critical | Certain | `rce`, `command-injection`, `oast`, `moderate` |
| `command-injection-timing` | OS Command Injection (Time-Based) | Detects blind OS command injection by confirming the response delay scales with the injected sleep duration | Critical | Tentative | `rce`, `command-injection`, `injection`, `heavy` |
| `crlf-injection` | CRLF Injection | Detects CRLF injection | Medium | Firm | `crlf`, `injection`, `moderate` |
| `xxe-generic` | XXE Generic | Detects XML external entity injection in generic XML endpoints | Critical | Certain | `injection`, `xxe`, `moderate` |
| `insecure-deserialization` | Insecure Deserialization | Detects insecure deserialization via error-based detection | High | Firm | `deserialization`, `rce`, `moderate` |
| `input-behavior-probe` | Input Behavior Probe | Detects behavior changes from header, path, debug param, and char probing | Info | Tentative | `injection`, `probe`, `moderate` |

### SSRF & Out-of-Band (OAST)

| Module ID | Name | Description | Severity | Confidence | Tags |
|---|---|---|---|---|---|
| `ssrf-detection` | SSRF Detection | Detects server-side request forgery via out-of-band and in-band techniques | High | Tentative | `ssrf`, `injection`, `moderate` |
| `oast-probe` | OAST Probe | Detects blind vulnerabilities via out-of-band callbacks (DNS/HTTP) | High | Certain | `injection`, `ssrf`, `rce`, `heavy` |
| `proxy-pingback` | Proxy Pingback | Detects open proxy/callback endpoints via OAST URL injection into proxy-related paths | High | Certain | `ssrf`, `misconfiguration`, `moderate` |

### Misconfiguration

| Module ID | Name | Description | Severity | Confidence | Tags |
|---|---|---|---|---|---|
| `cors-misconfiguration` | CORS Misconfiguration | Detects permissive CORS policies allowing unauthorized cross-origin access | Low | Firm | `misconfiguration`, `auth-bypass`, `moderate` |
| `spring-actuator-misconfig` | Spring Actuator Misconfiguration | Detects exposed Spring Boot actuator endpoints | High | Firm | `spring`, `java`, `misconfiguration`, `info-disclosure`, `light` |
| `host-header-injection` | Host Header Injection | Detects host header injection and routing manipulation | Medium | Firm | `injection`, `misconfiguration`, `moderate` |
| `web-cache-poisoning` | Web Cache Poisoning | Detects web cache poisoning via unkeyed header injection | High | Tentative | `cache-poisoning`, `header-security`, `moderate` |

### Access Control

| Module ID | Name | Description | Severity | Confidence | Tags |
|---|---|---|---|---|---|
| `forbidden-bypass` | 403/401 Forbidden Bypass | Detects bypass methods for 403/401 Forbidden responses | Medium | Firm | `auth-bypass`, `probe`, `moderate` |
| `http-method-tampering` | HTTP Method Tampering | Observes declared write methods and safely confirms OPTIONS override capability | Info | Firm | `misconfiguration`, `auth-bypass`, `moderate` |
| `csrf-verify` | CSRF Token Verification | Verifies CSRF token enforcement by removing, emptying, or randomizing tokens | High | Firm | `csrf`, `audit`, `moderate` |
| `idor-detection` | IDOR Detection | Detects missing authorization on object ID parameters (IDOR/BOLA) | High | Tentative | `idor`, `auth-bypass`, `moderate` |
| `mass-assignment` | Mass Assignment | Detects mass assignment / parameter pollution in JSON APIs | High | Firm | `injection`, `api`, `moderate` |
| `open-redirect` | Open Redirect | Detects open redirect vulnerabilities | Medium | Firm | `open-redirect`, `moderate` |

### Path Analysis

| Module ID | Name | Description | Severity | Confidence | Tags |
|---|---|---|---|---|---|
| `path-normalization` | Path Normalization | Detects path normalization vulnerabilities | High | Firm | `misconfiguration`, `lfi`, `traversal`, `moderate` |
| `nginx-off-by-slash` | Nginx Off-by-Slash | Detects Nginx alias traversal via missing trailing slash | High | Tentative | `nginx`, `misconfiguration`, `lfi`, `moderate` |
| `nginx-path-escape` | Nginx Path Escape Detection | Diff-based Nginx path escape detection (alias traversal, encoding bypass, semicolon injection) | Info | Tentative | `nginx`, `misconfiguration`, `moderate` |

### Differential & Behavior Detection

| Module ID | Name | Description | Severity | Confidence | Tags |
|---|---|---|---|---|---|
| `smart-behavior-detection` | Smart Behavior Detection | Diff-based injection detection via behavioral analysis | Info | Tentative | `behavior-analysis`, `injection`, `moderate` |
| `suspect-transform` | Suspect Transform Detection | Detects expression evaluation, quote consumption, unicode transformations | Suspect | Firm | `behavior-analysis`, `injection`, `moderate` |
| `backslash-transformation` | Backslash Transformation Detection | Detects escape sequence interpretation, backslash consumption, character handling | Suspect | Firm | `injection`, `probe`, `moderate` |

### Prototype Pollution

| Module ID | Name | Description | Severity | Confidence | Tags |
|---|---|---|---|---|---|
| `prototype-pollution` | Prototype Pollution | Detects server-side prototype pollution via JSON injection | High | Firm | `prototype-pollution`, `injection`, `javascript`, `moderate` |
| `client-prototype-pollution` | Client-Side Prototype Pollution | Detects client-side prototype pollution via JavaScript static analysis | Medium | Tentative | `prototype-pollution`, `xss`, `light` |

### Race Conditions

| Module ID | Name | Description | Severity | Confidence | Tags |
|---|---|---|---|---|---|
| `race-interference` | Race Interference Detection | Detects input storage, cross-contamination, and request interference races | Medium | Firm | `race-condition`, `heavy` |

### XML, JWT & HTTP Protocol

| Module ID | Name | Description | Severity | Confidence | Tags |
|---|---|---|---|---|---|
| `xml-saml-security` | XML SAML Security | SAML XML security checks (XXE + signature verification) | High | Firm | `injection`, `xxe`, `authentication`, `auth-bypass`, `moderate` |
| `jwt-vulnerability` | JWT Vulnerability | Detects JWT algorithm confusion and weak signing vulnerabilities | Critical | Certain | `jwt`, `auth-bypass`, `moderate` |
| `http-request-smuggling` | HTTP Request Smuggling | Detects HTTP request smuggling via CL.TE and TE.CL desync | Suspect | Tentative | `request-smuggling`, `heavy` |

### API & Endpoint Security

| Module ID | Name | Description | Severity | Confidence | Tags |
|---|---|---|---|---|---|
| `graphql-scan` | GraphQL Security Scanner | Tests GraphQL endpoints for introspection, injection, and batching vulnerabilities | Medium | Certain | `graphql`, `injection`, `info-disclosure`, `idor`, `bola`, `xss`, `dos`, `batching`, `console`, `moderate` |
| `file-upload-scan` | File Upload Scanner | Tests for arbitrary file upload and execution vulnerabilities | High | Certain | `rce`, `injection`, `heavy` |
| `default-credentials` | Default Credentials | Tests for default or common credential pairs on login endpoints | High | Certain | `auth-bypass`, `probe`, `moderate` |
| `sensitive-file-discovery` | Sensitive File Discovery | Probes for exposed sensitive files (.env, .git/config, dot files, log files, and more) | Medium | Tentative | `file-exposure`, `info-disclosure`, `moderate` |
| `jsonp-callback` | JSONP Callback Injection | Detects JSONP endpoints that allow cross-origin data theft via callback injection | Medium | Firm | `xss`, `info-disclosure`, `moderate` |

### Proxy & Utility

| Module ID | Name | Description | Severity | Confidence | Tags |
|---|---|---|---|---|---|
| `proxy-header-trust` | Proxy Header Trust | Cross-framework detection of proxy header trust issues via X-Forwarded-* header manipulation | High | Firm | `misconfiguration`, `header-security`, `moderate` |
| `api-rate-limit-bypass` | API Rate Limit Bypass | Detects rate limiting bypass via IP spoofing headers | Medium | Firm | `auth-bypass`, `probe`, `moderate` |
| `ws-cswsh` | WebSocket CSWSH | Tests for Cross-Site WebSocket Hijacking via insufficient origin validation | Medium | Firm | `csrf`, `session`, `moderate` |
| `swagger-exposure` | Exposed API Documentation | Detects publicly exposed Swagger/OpenAPI/Redoc documentation routes | Low | Firm | `api`, `discovery`, `swagger`, `openapi`, `exposure`, `info-leak`, `light` |
| `backup-file-discovery` | Backup File Discovery | Probes for exposed backup archives derived from hostname, common names, and year variants | Medium | Tentative | `sensitive-file`, `info-disclosure`, `moderate` |
| `angular-template-injection` | Angular Template Injection | Detects Angular template injection via expression evaluation | High | Firm | `angular`, `injection`, `ssti`, `moderate` |

### SQL Injection (Time-Based)

| Module ID | Name | Description | Severity | Confidence | Tags |
|---|---|---|---|---|---|
| `sqli-time-blind` | Blind SQL Injection (Time-Based) | Detects time-based blind SQL injection vulnerabilities | Suspect | Tentative | `injection`, `sqli`, `heavy` |

### SSRF & SSTI (Blind)

| Module ID | Name | Description | Severity | Confidence | Tags |
|---|---|---|---|---|---|
| `ssrf-blind` | Blind SSRF Detection | Detects blind server-side request forgery via OAST callbacks | High | Firm | `ssrf`, `injection`, `heavy` |
| `ssti-blind` | Blind Server-Side Template Injection (SSTI) | Detects blind SSTI via OAST callbacks and time-delay payloads | Critical | Firm | `injection`, `ssti`, `heavy` |

### Framework Security

#### Next.js

| Module ID | Name | Description | Severity | Confidence | Tags |
|---|---|---|---|---|---|
| `nextjs-data-leakage` | Next.js Data Route Leakage | Detects unauthorized access to Next.js data routes on auth-protected pages | High | Firm | `nextjs`, `javascript`, `authentication`, `info-disclosure`, `light` |
| `nextjs-middleware-bypass` | Next.js Middleware Bypass | Detects Next.js middleware authentication bypass via header injection and path manipulation | Critical | Firm | `nextjs`, `javascript`, `authentication`, `moderate` |
| `nextjs-image-ssrf` | Next.js Image Optimizer SSRF | Detects SSRF via the Next.js image optimization endpoint | High | Firm | `nextjs`, `javascript`, `ssrf`, `moderate` |
| `nextjs-draft-mode-exposure` | Next.js Draft Mode Exposure | Detects insecure or unprotected Next.js Draft/Preview Mode endpoints | High | Firm | `nextjs`, `javascript`, `misconfiguration`, `light` |
| `nextjs-version-audit` | Next.js Version Audit | Fingerprints Next.js version and maps to known CVE advisories | High | Firm | `nextjs`, `javascript`, `fingerprint`, `light` |
| `js-devserver-exposure` | JS Dev Server Exposure | Detects exposed JavaScript development server endpoints (webpack HMR, Vite, Nuxt) | Medium | Firm | `nextjs`, `nuxt`, `misconfiguration`, `info-disclosure`, `light` |

#### Spring / Java

| Module ID | Name | Description | Severity | Confidence | Tags |
|---|---|---|---|---|---|
| `spring-actuator-misconfig` | Spring Actuator Misconfiguration | Detects exposed Spring Boot actuator endpoints | High | Firm | `spring`, `java`, `misconfiguration`, `info-disclosure`, `light` |
| `spring-boot-admin-exposure` | Spring Boot Admin Exposure | Detects exposed Spring Boot Admin dashboards providing centralized access to actuator data | High | Firm | `spring`, `java`, `misconfiguration`, `info-disclosure`, `light` |
| `spring-cloud-config-exposure` | Spring Cloud Config Exposure | Detects exposed Spring Cloud Config Server endpoints leaking application configuration and secrets | Critical | Firm | `spring`, `java`, `misconfiguration`, `info-disclosure`, `light` |
| `spring-data-rest-exposure` | Spring Data REST Exposure | Detects auto-exposed Spring Data REST repository endpoints with HAL/HATEOAS discovery | Medium | Firm | `spring`, `java`, `api`, `info-disclosure`, `light` |
| `spring-debug-exposure` | Spring Debug Exposure | Detects Spring Boot debug endpoints, Whitelabel error pages, and verbose stack trace disclosure | Medium | Firm | `spring`, `java`, `misconfiguration`, `info-disclosure`, `light` |
| `spring-gateway-exposure` | Spring Gateway Exposure | Detects exposed Spring Cloud Gateway actuator endpoints revealing routes and filters | High | Firm | `spring`, `java`, `misconfiguration`, `info-disclosure`, `light` |
| `spring-h2-console-exposure` | Spring H2 Console Exposure | Detects exposed H2 database web consoles commonly left enabled in Spring Boot applications | Medium | Firm | `spring`, `java`, `misconfiguration`, `rce`, `light` |
| `spring-jolokia-exposure` | Spring Jolokia Exposure | Detects exposed Jolokia JMX endpoints providing HTTP access to Java Management Extensions | High | Firm | `spring`, `java`, `misconfiguration`, `info-disclosure`, `light` |
| `java-appserver-console` | Java App Server Console | Detects exposed admin consoles for WildFly/JBoss, WebLogic, and GlassFish/Payara | High | Firm | `java`, `tomcat`, `info-disclosure`, `probe`, `light` |
| `java-sensitive-files` | Java Sensitive Files | Detects Java-specific sensitive files: application configs, WEB-INF, META-INF, and build artifacts | Medium | Tentative | `java`, `sensitive-file`, `probe`, `light` |
| `tomcat-manager-exposure` | Tomcat Manager Exposure | Detects exposed Apache Tomcat Manager and Host Manager interfaces | High | Firm | `tomcat`, `java`, `misconfiguration`, `authentication`, `light` |

#### Django / Flask / FastAPI (Python)

| Module ID | Name | Description | Severity | Confidence | Tags |
|---|---|---|---|---|---|
| `django-admin-exposure` | Django Admin Exposure | Probes for exposed Django admin panel and login page | Low | Firm | `django`, `python`, `info-disclosure`, `probe`, `light` |
| `django-browsable-api-exposure` | Django Browsable API Exposure | Detects DRF browsable API by requesting endpoints with Accept: text/html | Info | Firm | `django`, `python`, `info-disclosure`, `probe`, `light` |
| `django-debug-exposure` | Django Debug Exposure | Triggers errors to detect Django DEBUG=True information disclosure | High | Firm | `django`, `python`, `misconfiguration`, `info-disclosure`, `moderate` |
| `django-debug-toolbar-exposure` | Django Debug Toolbar Exposure | Detects exposed django-debug-toolbar panels and render endpoints | High | Firm | `django`, `python`, `misconfiguration`, `info-disclosure`, `light` |
| `flask-werkzeug-debugger` | Flask Werkzeug Debugger | Detects exposed Werkzeug interactive debugger enabling remote code execution | Critical | Certain | `flask`, `python`, `rce`, `misconfiguration`, `light` |
| `fastapi-docs-exposure` | FastAPI Docs Exposure | Probes for exposed FastAPI interactive API documentation endpoints | Info | Firm | `fastapi`, `python`, `info-disclosure`, `probe`, `light` |
| `fastapi-auth-inconsistency` | FastAPI Auth Inconsistency | Fetches OpenAPI schema and finds unprotected operations | Medium | Firm | `fastapi`, `python`, `auth-bypass`, `audit`, `moderate` |

#### Laravel / Symfony / PHP

| Module ID | Name | Description | Severity | Confidence | Tags |
|---|---|---|---|---|---|
| `laravel-admin-exposure` | Laravel Admin Exposure | Detects unauthenticated access to Laravel admin panels, API documentation, and GraphQL endpoints | High | Tentative | `laravel`, `php`, `info-disclosure`, `probe`, `light` |
| `laravel-devtool-exposure` | Laravel Developer Tool Exposure | Detects exposed Laravel developer tools: Web Tinker, Clockwork, Pulse, and Log Viewer | High | Firm | `laravel`, `php`, `misconfiguration`, `info-disclosure`, `light` |
| `laravel-ignition-rce` | Laravel Ignition RCE | Detects exposed Ignition endpoints and flags CVE-2021-3129 RCE candidates | Critical | Firm | `laravel`, `php`, `rce`, `light` |
| `laravel-misconfig` | Laravel Misconfiguration | Detects Laravel debug mode, exposed debugbar, application logs, and configuration leaks | High | Firm | `laravel`, `php`, `misconfiguration`, `info-disclosure`, `moderate` |
| `laravel-sensitive-files` | Laravel Sensitive Files | Detects Laravel-specific sensitive files: PHPUnit config, SQLite DB, storage internals, eval-stdin, and wrong document root | Medium | Tentative | `laravel`, `php`, `sensitive-file`, `probe`, `light` |
| `symfony-misconfig` | Symfony Misconfiguration | Detects exposed Symfony profiler, debug toolbar, dev front controller, and configuration leaks | High | Firm | `symfony`, `php`, `misconfiguration`, `info-disclosure`, `light` |
| `php-composer-exposure` | PHP Composer Exposure | Detects exposed Composer manifests, vendor directory, and PHPUnit dev endpoints | High | Firm | `php`, `file-exposure`, `info-disclosure`, `light` |
| `php-debug-exposure` | PHP Debug Exposure | Detects exposed phpinfo pages, PHP-FPM status endpoints, and phpMyAdmin instances | Medium | Firm | `php`, `misconfiguration`, `info-disclosure`, `light` |
| `php-framework-debug` | PHP Framework Debug Exposure | Detects exposed debug endpoints for Yii, CodeIgniter, CakePHP, and other PHP frameworks | Medium | Firm | `php`, `misconfiguration`, `info-disclosure`, `light` |
| `php-path-info-misconfig` | PHP PATH_INFO Misconfiguration | Detects cgi.fix_pathinfo routing ambiguity allowing script path manipulation | Medium | Firm | `php`, `misconfiguration`, `light` |
| `php-source-disclosure` | PHP Source Disclosure | Detects PHP source code disclosure via .phps handlers, misconfigured extensions, and static file serving | High | Firm | `php`, `info-disclosure`, `file-exposure`, `light` |

#### Rails (Ruby)

| Module ID | Name | Description | Severity | Confidence | Tags |
|---|---|---|---|---|---|
| `rails-info-exposure` | Rails Info Exposure | Detects exposed Rails development and debug endpoints in production | High | Firm | `rails`, `ruby`, `info-disclosure`, `misconfiguration`, `light` |
| `rails-admin-dashboard` | Rails Admin Dashboard | Detects exposed Rails ecosystem admin panels and dashboard UIs | High | Firm | `rails`, `ruby`, `misconfiguration`, `info-disclosure`, `light` |
| `rails-sensitive-files` | Rails Sensitive Files | Detects exposed Rails configuration files, credentials, and artifacts | Medium | Tentative | `rails`, `ruby`, `file-exposure`, `info-disclosure`, `light` |
| `rails-action-mailbox-probe` | Rails Action Mailbox Probe | Detects exposed Rails Action Mailbox ingress endpoints that may accept unauthorized submissions | Medium | Firm | `rails`, `ruby`, `misconfiguration`, `light` |
| `rails-active-storage-probe` | Rails Active Storage Probe | Detects exposed Rails Active Storage direct upload and Action Mailbox ingress endpoints | Medium | Tentative | `rails`, `ruby`, `misconfiguration`, `file-exposure`, `light` |

#### Express (Node.js)

| Module ID | Name | Description | Severity | Confidence | Tags |
|---|---|---|---|---|---|
| `express-debug-probe` | Express Debug Probe | Triggers error responses in Express/NestJS apps to detect stack trace and debug info leakage | Low | Firm | `express`, `misconfiguration`, `info-disclosure`, `moderate` |
| `express-directory-listing` | Express Directory Listing | Detects directory listing exposure via serve-index or similar middleware | Low | Firm | `express`, `info-disclosure`, `misconfiguration`, `light` |
| `express-trust-proxy-misconfig` | Express Trust Proxy Misconfiguration | Detects Express trust proxy misconfiguration via X-Forwarded-* header manipulation | Medium | Firm | `express`, `misconfiguration`, `moderate` |

#### ASP.NET / IIS

| Module ID | Name | Description | Severity | Confidence | Tags |
|---|---|---|---|---|---|
| `aspnet-blazor-exposure` | ASP.NET Blazor Exposure | Detects exposed Blazor WebAssembly assemblies and Blazor Server endpoints | Medium | Firm | `aspnet`, `info-disclosure`, `probe`, `light` |
| `aspnet-health-exposure` | ASP.NET Health Endpoint Exposure | Detects exposed ASP.NET health checks, monitoring dashboards, and metrics endpoints | Medium | Firm | `aspnet`, `info-disclosure`, `probe`, `light` |
| `aspnet-identity-probe` | ASP.NET Identity Probe | Detects exposed ASP.NET Identity endpoints, IdentityServer discovery, and authentication misconfigurations | Medium | Firm | `aspnet`, `auth-bypass`, `probe`, `moderate` |
| `aspnet-misconfig` | ASP.NET Misconfiguration | Detects ASP.NET/IIS misconfigurations including exposed diagnostics, debug endpoints, and verbose errors | High | Firm | `aspnet`, `misconfiguration`, `info-disclosure`, `light` |
| `aspnet-sensitive-files` | ASP.NET Sensitive Files | Probes for exposed ASP.NET configuration files, backups, and sensitive directories | Medium | Tentative | `aspnet`, `sensitive-file`, `probe`, `light` |
| `aspnet-service-exposure` | ASP.NET Service Exposure | Detects exposed ASP.NET service endpoints including ASMX, WCF, OData, and legacy service paths | Medium | Firm | `aspnet`, `info-disclosure`, `probe`, `light` |
| `aspnet-viewstate-scan` | ASP.NET ViewState Scan | Tests for ASP.NET ViewState MAC disabled, event validation bypass, and cookieless sessions | High | Firm | `aspnet`, `misconfiguration`, `moderate` |
| `iis-shortname-discovery` | IIS Short Filename Discovery | Enumerates IIS 8.3 short filenames via tilde-based oracle (per-host) | Medium | Certain | `iis`, `aspnet`, `info-disclosure`, `heavy` |

#### Firebase

| Module ID | Name | Description | Severity | Confidence | Tags |
|---|---|---|---|---|---|
| `firebase-auth-misconfig` | Firebase Auth Misconfiguration | Detects Firebase Authentication misconfigurations via Identity Toolkit probing | Medium | Firm | `firebase`, `misconfiguration`, `auth-bypass`, `moderate` |
| `firebase-functions-exposure` | Firebase Functions Exposure | Detects unauthenticated Firebase Cloud Functions and verbose error leakage | Medium | Firm | `firebase`, `info-disclosure`, `probe`, `moderate` |
| `firebase-misconfig` | Firebase Misconfiguration | Detects exposed Firebase configuration, security rules, and credential files | High | Firm | `firebase`, `misconfiguration`, `sensitive-file`, `moderate` |
| `firebase-rtdb-exposure` | Firebase RTDB Exposure | Detects publicly readable Firebase Realtime Database instances | Medium | Certain | `firebase`, `info-disclosure`, `moderate` |
| `firebase-storage-exposure` | Firebase Storage Exposure | Detects publicly accessible Firebase Cloud Storage buckets | High | Certain | `firebase`, `cloud`, `info-disclosure`, `moderate` |

#### Cloud Infrastructure

| Module ID | Name | Description | Severity | Confidence | Tags |
|---|---|---|---|---|---|
| `cloud-bucket-takeover` | Cloud Bucket Takeover | Detects dangling cloud storage buckets vulnerable to takeover | High | Firm | `cloud`, `misconfiguration`, `moderate` |
| `cloud-origin-bypass` | Cloud Origin Bypass | Detects direct access to cloud storage origins bypassing CDN security controls | Medium | Firm | `cloud`, `auth-bypass`, `moderate` |
| `cloud-public-read` | Cloud Public Read | Detects publicly readable sensitive paths on cloud storage endpoints | High | Firm | `cloud`, `info-disclosure`, `sensitive-file`, `moderate` |
| `cloud-storage-listing` | Cloud Storage Listing | Detects publicly listable S3 buckets and Azure containers | High | Certain | `cloud`, `info-disclosure`, `light` |

#### CMS (WordPress, Drupal, Joomla, Magento)

| Module ID | Name | Description | Severity | Confidence | Tags |
|---|---|---|---|---|---|
| `wp-misconfig` | WordPress Misconfiguration | Detects exposed WordPress configuration files, debug logs, and dangerous endpoints | High | Firm | `wordpress`, `cms`, `php`, `misconfiguration`, `light` |
| `wp-user-enum` | WordPress User Enumeration | Detects WordPress user enumeration via author archives and REST API | Info | Certain | `wordpress`, `cms`, `php`, `authentication`, `light` |
| `wp-xmlrpc` | WordPress XML-RPC Abuse | Detects enabled WordPress XML-RPC with multicall brute-force and pingback abuse potential | Medium | Firm | `wordpress`, `cms`, `php`, `misconfiguration`, `light` |
| `wp-ajax-exposure` | WordPress AJAX Action Exposure | Detects publicly accessible WordPress AJAX actions from plugins with known vulnerabilities | High | Firm | `wordpress`, `cms`, `php`, `misconfiguration`, `light` |
| `drupal-misconfig` | Drupal Misconfiguration | Detects exposed Drupal configuration files, update scripts, installer, debug settings, and directory listings | High | Firm | `drupal`, `php`, `misconfiguration`, `info-disclosure`, `moderate` |
| `drupal-user-enum` | Drupal User Enumeration | Detects Drupal user enumeration via user profile paths and JSON:API | Info | Certain | `drupal`, `php`, `info-disclosure`, `probe`, `moderate` |
| `joomla-misconfig` | Joomla Misconfiguration | Detects exposed Joomla configuration backups, log/temp directories, backup archives, and debug settings | High | Firm | `joomla`, `php`, `misconfiguration`, `info-disclosure`, `moderate` |
| `joomla-user-enum` | Joomla User Enumeration | Detects Joomla user enumeration via registration form, API endpoints, and admin login exposure | Info | Firm | `joomla`, `php`, `info-disclosure`, `probe`, `moderate` |
| `magento-misconfig` | Magento Misconfiguration | Detects exposed Magento setup wizard, downloader, version files, and admin panels | High | Firm | `magento`, `php`, `cms`, `misconfiguration`, `light` |
| `cms-installer-exposure` | CMS Installer Exposure | Detects exposed CMS installation wizards for WordPress, Drupal, and Joomla | Critical | Firm | `wordpress`, `drupal`, `joomla`, `misconfiguration`, `probe`, `light` |

---

## Selected Passive Modules

Passive modules analyze existing request/response pairs without sending new traffic.

### XSS

| Module ID | Name | Description | Severity | Confidence | Tags |
|---|---|---|---|---|---|
| `dom-xss-detect` | DOM XSS Detect | Detects potential DOM-based XSS patterns in responses | Low | Firm | `xss`, `javascript`, `light` |

### Authentication & Session

| Module ID | Name | Description | Severity | Confidence | Tags |
|---|---|---|---|---|---|
| `auth-headers-detect` | Auth Headers Detect | Detects authorization headers in requests | Info | Tentative | `authentication`, `info-disclosure`, `light` |
| `jwt-weak-secret` | JWT Weak Secret Detection | Detects JWTs with weak HMAC secrets, non-cryptographic signatures, and algorithm confusion | High | Firm | `authentication`, `cryptography`, `session`, `moderate` |
| `cookie-security-detect` | Cookie Security Detect | Detects insecure cookie attributes in HTTP responses | Low | Certain | `session`, `misconfiguration`, `header-security`, `light` |
| `password-autocomplete-detect` | Password Autocomplete Detect | Observes likely password fields without current-password or new-password semantics | Info | Certain | `authentication`, `misconfiguration`, `light` |

### Injection Signals

| Module ID | Name | Description | Severity | Confidence | Tags |
|---|---|---|---|---|---|
| `sql-syntax-detect` | SQL Syntax in Request Detection | Detects SQL syntax in HTTP request parameter values | Info | Firm | `sqli`, `injection`, `light` |
| `serialized-object-detect` | Serialized Object Detection | Detects serialized Java/PHP/.NET/Python/Ruby/Node.js objects in request parameters (incl. base64-wrapped) | Low | Firm | `deserialization`, `light` |
| `input-reflection-detect` | Input Reflection Detect | Detects request parameter values reflected in responses | Info | Tentative | `xss`, `injection`, `light` |
| `base64-data-detect` | Base64 Data Detect | Identifies interesting base64 encoded data like JSON, PHP Object in requests/responses | Info | Tentative | `info-disclosure`, `deserialization`, `light` |

### Information Disclosure

| Module ID | Name | Description | Severity | Confidence | Tags |
|---|---|---|---|---|---|
| `secret-detect` | Secret Detection | Detects leaked secrets and credentials in HTTP responses | High | Firm | `info-disclosure`, `file-exposure`, `light` |
| `info-disclosure-detect` | Info Disclosure Detect | Detects information disclosure patterns in HTTP responses | Low | Firm | `info-disclosure`, `light` |
| `error-message-detect` | Error Message Detect | Observes corroborated framework or database errors in error responses | Info | Firm | `info-disclosure`, `light` |
| `sourcemap-detect` | Sourcemap Exposure Detect | Detects exposed JavaScript sourcemaps in production responses | Low | Firm | `javascript`, `info-disclosure`, `light` |
| `sensitive-url-params` | Sensitive URL Params | Detects sensitive data in URL query parameters | Medium | Firm | `info-disclosure`, `light` |
| `content-type-mismatch` | Content Type Mismatch | Detects mismatches between Content-Type header and response body | Low | Firm | `misconfiguration`, `header-security`, `light` |

### Security Headers & Configuration

| Module ID | Name | Description | Severity | Confidence | Tags |
|---|---|---|---|---|---|
| `security-headers-missing` | Security Headers Missing | Detects missing/weak HTTP security headers and cacheable sensitive responses | Info | Certain | `header-security`, `misconfiguration`, `light` |
| `mixed-content-detect` | Mixed Content Detect | Classifies insecure subresources and HTTP form submissions on HTTPS pages | Low | Certain | `misconfiguration`, `cryptography`, `light` |

### CORS & Redirect

| Module ID | Name | Description | Severity | Confidence | Tags |
|---|---|---|---|---|---|
| `cors-headers-detect` | CORS Headers Detect | Passively detects permissive CORS headers in responses | Low | Firm | `misconfiguration`, `header-security`, `light` |
| `openredirect-params` | Open Redirect Params | Detects URL parameters commonly used for open redirects | Info | Tentative | `open-redirect`, `light` |
| `oauth-facebook-detect` | Facebook OAuth Detect | Detects Facebook OAuth redirect parameters for security analysis | Info | Firm | `authentication`, `session`, `light` |

### Access Control

| Module ID | Name | Description | Severity | Confidence | Tags |
|---|---|---|---|---|---|
| `csrf-detect` | CSRF Detection | Flags state-changing requests missing anti-CSRF protections | Medium | Tentative | `csrf`, `session`, `light` |
| `idor-params-detect` | IDOR Parameter Detection | Detects parameters that may reference object identifiers (IDOR/BOLA triage) | Info | Tentative | `idor`, `authentication`, `light` |

### Cryptography

| Module ID | Name | Description | Severity | Confidence | Tags |
|---|---|---|---|---|---|
| `crypto-weakness-detect` | Cryptographic Weakness Detection | Detects weak cryptographic patterns in HTTP traffic | Medium | Tentative | `cryptography`, `misconfiguration`, `light` |

### Anomaly Detection

| Module ID | Name | Description | Severity | Confidence | Tags |
|---|---|---|---|---|---|
| `anomaly-ranking` | Anomaly Ranking | Statistical anomaly detection across per-host response batches | Suspect | Tentative | `behavior-analysis`, `light` |

### JS Framework Security (Runtime Analysis)

| Module ID | Name | Description | Severity | Confidence | Tags |
|---|---|---|---|---|---|
| `js-framework-fingerprint` | JS Framework Fingerprint | Identifies JavaScript frameworks (Next.js, Nuxt, Angular, React, Remix, SvelteKit, Gatsby) | Info | Certain | `javascript`, `fingerprint`, `nextjs`, `angular`, `react`, `light` |
| `ssr-data-exposure` | SSR Data Exposure | Detects sensitive data leaked in server-side rendered state blobs | Medium | Firm | `javascript`, `info-disclosure`, `light` |
| `cache-auth-misconfiguration` | Cache-Auth Misconfiguration | Detects cacheable responses with user-specific data missing Vary headers | Medium | Tentative | `misconfiguration`, `cache-poisoning`, `session`, `light` |
| `server-action-auth` | Server Action Auth Check | Detects Next.js Server Actions missing authorization checks | Medium | Tentative | `nextjs`, `javascript`, `authentication`, `light` |
| `nextjs-config-audit` | Next.js Config Audit | Detects insecure Next.js configuration patterns | Medium | Firm | `nextjs`, `javascript`, `misconfiguration`, `light` |
| `client-auth-guard` | Client Auth Guard Check | Detects client-only auth guards without server-side enforcement | Info | Tentative | `authentication`, `javascript`, `light` |
| `cache-data-leak` | Cache Data Leak | Detects cache and static generation patterns that may leak user data | Medium | Tentative | `info-disclosure`, `cache-poisoning`, `light` |

### JS Framework Security (Source Analysis)

| Module ID | Name | Description | Severity | Confidence | Tags |
|---|---|---|---|---|---|
| `unsafe-html-sink` | Unsafe HTML Sink | Detects raw HTML injection sinks in JS/TS framework code | Low | Firm | `xss`, `javascript`, `light` |
| `insecure-token-storage` | Insecure Token Storage | Detects auth tokens stored in localStorage/sessionStorage | Medium | Firm | `authentication`, `session`, `javascript`, `light` |
| `env-secret-exposure` | Environment Secret Exposure | Detects credential-shaped values in public environment variables and served dotenv files | Medium | Tentative | `info-disclosure`, `file-exposure`, `light` |
| `build-misconfig-detect` | Build Misconfiguration Detect | Detects build and deployment misconfigurations in framework config files | High | Firm | `misconfiguration`, `info-disclosure`, `javascript`, `light` |

### Framework Fingerprinting

| Module ID | Name | Description | Severity | Confidence | Tags |
|---|---|---|---|---|---|
| `aspnet-fingerprint` | ASP.NET Fingerprint | Identifies ASP.NET and IIS installations from response headers, cookies, and body patterns | Info | Certain | `aspnet`, `fingerprint`, `light` |
| `aspnet-viewstate-detect` | ASP.NET ViewState Detect | Detects ASP.NET ViewState issues including missing encryption, CSRF tokens, and large payloads | Low | Firm | `aspnet`, `misconfiguration`, `session`, `light` |
| `django-fingerprint` | Django Fingerprint | Identifies Django installations from response headers, cookies, and body patterns | Info | Certain | `django`, `python`, `fingerprint`, `light` |
| `express-fingerprint` | Express/NestJS Fingerprint | Identifies Express.js and NestJS applications via response headers and error body patterns | Info | Certain | `express`, `nodejs`, `fingerprint`, `light` |
| `fastapi-fingerprint` | FastAPI Fingerprint | Identifies FastAPI/Starlette/Uvicorn installations from response headers, body patterns, and endpoints | Info | Certain | `fastapi`, `python`, `fingerprint`, `light` |
| `firebase-fingerprint` | Firebase Fingerprint | Identifies Firebase usage and detects leaked Firebase secrets in responses | Info | Certain | `firebase`, `cloud`, `fingerprint`, `light` |
| `flask-fingerprint` | Flask Fingerprint | Identifies Flask/Werkzeug installations from response headers, cookies, and body patterns | Info | Certain | `flask`, `python`, `fingerprint`, `light` |
| `laravel-fingerprint` | Laravel Fingerprint | Identifies Laravel installations from response headers, cookies, and body patterns | Info | Certain | `laravel`, `php`, `fingerprint`, `light` |
| `rails-fingerprint` | Rails Fingerprint | Identifies Ruby on Rails installations from response headers, cookies, and body patterns | Info | Certain | `rails`, `ruby`, `fingerprint`, `light` |
| `spring-fingerprint` | Spring Fingerprint | Identifies Spring Boot/Spring MVC applications from response headers, cookies, error pages, and body patterns | Info | Certain | `spring`, `java`, `fingerprint`, `light` |
| `drupal-fingerprint` | Drupal Fingerprint | Identifies Drupal installations and detects core version, major generation (7/8/9/10/11), and contributed modules | Info | Certain | `drupal`, `cms`, `fingerprint`, `light` |
| `joomla-fingerprint` | Joomla Fingerprint | Identifies Joomla installations and enumerates components, modules, and plugins from asset paths | Info | Certain | `joomla`, `cms`, `fingerprint`, `light` |
| `wp-fingerprint` | WordPress Fingerprint | Identifies WordPress installations and enumerates core version, plugins, and themes | Info | Certain | `wordpress`, `cms`, `php`, `fingerprint`, `light` |

### API & Protocol Analysis

| Module ID | Name | Description | Severity | Confidence | Tags |
|---|---|---|---|---|---|
| `api-version-detect` | API Version Detect | Detects API versioning patterns in URLs, headers, and response bodies | Info | Certain | `api`, `fingerprint`, `light` |
| `graphql-introspection-detect` | GraphQL Introspection Leak Detect | Detects GraphQL introspection responses that expose the full API schema | Info | Firm | `graphql`, `api`, `info-disclosure`, `light` |
| `grpc-web-detect` | gRPC-Web Detect | Detects gRPC-Web protocol usage in HTTP traffic | Info | Firm | `api`, `fingerprint`, `light` |
| `endpoint-classifier` | Endpoint Classifier | Tags HTTP records with semantic labels based on request/response characteristics | Info | Certain | `utility`, `light` |

### Security Headers & Policy

| Module ID | Name | Description | Severity | Confidence | Tags |
|---|---|---|---|---|---|
| `csp-weakness-audit` | CSP Weakness Audit | Detects weak or unsafe Content-Security-Policy directives | Low | Firm | `header-security`, `misconfiguration`, `xss`, `light` |
| `permissions-policy-detect` | Permissions Policy Detect | Detects missing or overly permissive Permissions-Policy headers | Info | Certain | `header-security`, `misconfiguration`, `light` |
| `hsts-preload-audit` | HSTS Preload Audit | Audits Strict-Transport-Security header for preload readiness | Low | Certain | `header-security`, `cryptography`, `light` |
| `subresource-integrity-detect` | Subresource Integrity Detect | Observes truly cross-origin scripts and stylesheets without valid SRI | Info | Certain | `header-security`, `javascript`, `light` |
| `cors-vary-origin-missing` | CORS Vary Origin Missing | Detects dynamic CORS responses missing Vary: Origin header enabling cache poisoning | Low | Firm | `misconfiguration`, `header-security`, `cache-poisoning`, `light` |

### Cloud & Firebase

| Module ID | Name | Description | Severity | Confidence | Tags |
|---|---|---|---|---|---|
| `cloud-storage-fingerprint` | Cloud Storage Fingerprint | Detects S3, GCS, and Azure Blob Storage endpoints in HTTP responses | Info | Certain | `cloud`, `fingerprint`, `light` |
| `cloud-storage-error-info` | Cloud Storage Error Info | Extracts bucket names and regions from cloud storage error responses | Info | Certain | `cloud`, `info-disclosure`, `light` |
| `cloud-signed-url-leak` | Cloud Signed URL Leak | Detects leaked cloud storage signed URLs and SAS tokens in responses | Medium | Firm | `cloud`, `info-disclosure`, `light` |

### CMS Detection

| Module ID | Name | Description | Severity | Confidence | Tags |
|---|---|---|---|---|---|
| `drupal-api-detect` | Drupal API Exposure | Detects exposed Drupal JSON:API and REST endpoints from response content | Low | Certain | `drupal`, `cms`, `api`, `light` |
| `joomla-api-detect` | Joomla API Exposure | Detects exposed Joomla Web Services API endpoints and CORS misconfigurations | Low | Certain | `joomla`, `cms`, `api`, `light` |
| `wp-rest-api-detect` | WordPress REST API Exposure | Detects exposed WordPress REST API namespaces and sensitive endpoints | Low | Certain | `wordpress`, `cms`, `php`, `api`, `light` |

### Advanced JS Framework Analysis

| Module ID | Name | Description | Severity | Confidence | Tags |
|---|---|---|---|---|---|
| `nextjs-dynamic-param-audit` | Next.js Dynamic Param Audit | Detects unsafe usage of dynamic route params without validation | Medium | Tentative | `nextjs`, `javascript`, `injection`, `light` |
| `nextauth-config-audit` | NextAuth.js Configuration Audit | Detects insecure NextAuth.js session and cookie configurations | Medium | Firm | `nextjs`, `javascript`, `authentication`, `session`, `light` |
| `nuxt-config-audit` | Nuxt Config Audit | Detects insecure Nuxt configuration patterns and sensitive data in Nuxt state | Medium | Firm | `nuxt`, `javascript`, `misconfiguration`, `light` |
| `remix-loader-exposure` | Remix Loader Exposure | Detects sensitive data leaked through Remix loader data and context | Medium | Firm | `javascript`, `info-disclosure`, `light` |
| `ssr-hydration-xss` | SSR Hydration XSS Detection | Detects potential XSS in server-side rendered JSON hydration scripts | High | Tentative | `xss`, `javascript`, `light` |
| `server-action-bind-audit` | Server Action Bind Audit | Detects Server Action .bind() with sensitive identifiers risking IDOR | Medium | Tentative | `nextjs`, `javascript`, `idor`, `light` |
| `server-action-input-audit` | Server Action Input Audit | Detects Next.js Server Actions missing runtime input validation | Medium | Tentative | `nextjs`, `javascript`, `injection`, `light` |
| `server-only-boundary-audit` | Server-Only Boundary Audit | Detects server-side modules leaked into client component bundles | Medium | Tentative | `nextjs`, `javascript`, `info-disclosure`, `light` |
| `javascript-uri-sink` | JavaScript URI Sink Detection | Detects javascript: URIs reflected in href/src attributes | Medium | Tentative | `xss`, `javascript`, `light` |
| `wasm-module-detect` | WebAssembly Module Detect | Detects WebAssembly modules and WASM instantiation in HTTP responses | Info | Certain | `javascript`, `fingerprint`, `light` |

### Session & Authentication (Passive)

| Module ID | Name | Description | Severity | Confidence | Tags |
|---|---|---|---|---|---|
| `express-session-audit` | Express Session Audit | Audits Express.js session cookies for default naming, excessive expiry, and session proliferation | Low | Firm | `express`, `nodejs`, `session`, `misconfiguration`, `light` |
| `jwt-claims-detect` | JWT Claim Analyzer | Analyzes JWT claims for security misconfigurations | Medium | Firm | `authentication`, `session`, `cryptography`, `light` |
| `jackson-deserialize-detect` | Jackson Deserialization Detect | Detects Jackson polymorphic typing indicators and Java deserialization error patterns in responses | Low | Tentative | `java`, `deserialization`, `light` |
| `python-debug-detect` | Python Debug Detect | Detects Python tracebacks, debug pages, and path disclosure in responses | High | Firm | `python`, `info-disclosure`, `misconfiguration`, `light` |
| `rails-debug-detect` | Rails Debug Detect | Detects Rails debug exception pages, Better Errors, Web Console, and ActiveRecord errors in responses | High | Firm | `rails`, `ruby`, `info-disclosure`, `misconfiguration`, `light` |
| `rails-action-cable-detect` | Rails Action Cable Detect | Passively detects Action Cable WebSocket endpoints and configuration in responses | Info | Firm | `rails`, `ruby`, `fingerprint`, `light` |
| `rails-active-storage-detect` | Rails Active Storage Detect | Passively detects Active Storage URLs and direct upload references in responses | Info | Certain | `rails`, `ruby`, `fingerprint`, `file-exposure`, `light` |
| `sensitive-api-fields-detect` | Sensitive API Fields Detect | Flags JSON API responses containing sensitive field names like passwords, API keys, and PII | Medium | Tentative | `api`, `info-disclosure`, `light` |
