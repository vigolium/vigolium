# Changelog

All notable changes to `jstangle` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1] - 2026-07-11

First release under the `jstangle` name — a rename of the previous `jsscan`
helper (see [0.1.0]) plus a substantial round of enhancements. `jstangle` is the
JavaScript intelligence engine inside Vigolium: it deobfuscates, beautifies, and
AST-parses JavaScript bundles to surface hidden endpoints, request shapes, and
other useful information.

### Added

- Deobfuscation + beautification pipeline (webcrack-backed, loaded lazily) with
  selectable rewrite levels (`strict` | `standard` (default) | `aggressive`).
- Typed analysis-result envelope with per-record confidence and provenance, plus
  contained artifacts for large transformed/beautified documents.
- Typed record families: `httpRequest`, `domFlow`, `assetReference`,
  `graphqlOperation`, `websocket`, `eventSource`, `clientRoute`, and
  `browserSecurityFlow`.
- Analysis profiles so each caller runs only the stages it consumes:
  `endpoints`, `dom-security`, `beautify`, `discovery`, `discovery-lite`,
  `full`, and `inspect`.
- CLI now accepts JavaScript from a file path, raw JS as the first positional
  argument, or piped stdin.
- `--capabilities` machine-readable build/capability contract and a persistent
  length-framed `--worker` transport for the Go scanner.
- Version tracking single-sourced from `package.json` (compiled into the binary
  as the reported `toolVersion` / `--version`).
- Standalone, publishable CLI package `@vigolium/jstangle` (`bun run npm-publish`).

### Changed

- Renamed the project and helper binary from `jsscan` to `jstangle`.
- Relicensed under the MIT License.

## [0.1.0]

Previous release, shipped under the name `jsscan` — the endpoint/request
extraction helper that preceded the `jstangle` rename and enhancements.

[0.1.1]: https://github.com/vigolium/jstangle/releases/tag/v0.1.1
[0.1.0]: https://github.com/vigolium/jstangle/releases/tag/v0.1.0
