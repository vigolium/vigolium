// Package agent implements the agentic scan engine that powers the autopilot,
// swarm, and query modes. It owns prompt templates and rendering, context
// enrichment, the autopilot pipeline and swarm runners, structured output
// parsing (findings, HTTP records, attack plans, triage results, source
// analysis), and ingestion of results into the database. All AI dispatch is
// routed through the in-process olium engine via olium_adapter.go; there are no
// subprocess SDK backends. See docs/agentic-scan/agent-mode.md.
package agent
