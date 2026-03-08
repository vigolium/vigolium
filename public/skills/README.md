# vigolium-scanner

Claude Code skill for operating the [Vigolium](https://github.com/vigolium/vigolium) web vulnerability scanner CLI.

## What is Vigolium?

Vigolium is a high-fidelity web vulnerability scanner built for security professionals. It combines traditional DAST scanning with AI-powered analysis to find vulnerabilities in web applications. Key capabilities:

- **Multi-phase scanning** — discovery, spidering, SPA analysis, dynamic assessment, and SAST
- **Flexible input** — scan URLs directly, or import from OpenAPI specs, Burp exports, HAR files, cURL commands, and more
- **AI agent modes** — autonomous scanning, multi-phase pipelines, and AI-assisted code review
- **Extensible** — write custom scanner modules in JavaScript
- **Source-aware** — whitebox scanning that combines static analysis with dynamic testing

## Install

```bash
npx skills add vigolium/skills vigolium-scanner
```

## Example Queries

Once installed, you can ask Claude Code things like:

```
scan https://example.com for vulnerabilities

scan this OpenAPI spec against my staging server

import this Burp export and run only SQL injection modules

run discovery on https://example.com and show me the results

start the vigolium server with auto-scan enabled

run an AI agent autopilot scan on https://api.example.com

write a custom JS extension that checks for missing security headers

export all findings as an HTML report

show me all high severity findings from the last scan

set up a whitebox scan using the source code in ./src
```
