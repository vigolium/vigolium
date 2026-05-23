// Package modules defines the scanner module system: the base Module interface
// plus the ActiveModule and PassiveModule interfaces, the optional capability
// interfaces (ContextualActiveModule, Prioritized, VulnClassifier, TechAware,
// TimeoutHinter, Flusher, ScopeAwareModule), and the thread-safe Registry that
// the executor dispatches through. Concrete scanners live under active/ and
// passive/; modkit/ provides base types and default behavior, infra/ provides
// block detection and request filtering, and modtest/ provides a Docker-free
// unit-test harness. See docs/development/developing-modules.md.
package modules
