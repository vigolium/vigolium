package archon

// HarnessName is the on-disk identifier for the archon audit harness.
// Used as the source-folder name (`<source>/archon/`), session subdir
// suffix, env-var prefix, finding-id prefix, and AgenticScan.Mode value.
// Kept as a constant so the launcher and parser stay in lockstep
// without each side hard-coding the literal "archon".
const HarnessName = "archon"
