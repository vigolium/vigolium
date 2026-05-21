package audit

// HarnessName is the on-disk identifier for the vigolium-audit harness.
// Drives the env-var prefix, finding-id prefix, and AgenticScan.Mode
// value. The on-disk output dir (`<source>/vigolium-results/`) and the
// session subdir (`<session>/vigolium-results/`) are set independently
// on HarnessSpec to match the upstream binary's output directory name.
const HarnessName = "audit"
