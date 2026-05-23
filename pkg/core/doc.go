// Package core contains the scan Executor — the central orchestrator of a
// native scan. The Executor receives HttpRequestResponse work items, dispatches
// them to registered active and passive modules through a bounded worker pool,
// and collects ResultEvent findings. It owns scope filtering, per-host rate
// limiting, pre/post hooks, per-module timeouts, context-based cancellation, and
// the post-EOF feedback drain that lets passive modules re-inject discovered
// requests. Subpackages provide the rate limiter, network dialer, service
// container, and scan statistics.
package core
