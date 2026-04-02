package archon

import "embed"

//go:embed agent-defs
var AgentsFS embed.FS

//go:embed command-defs/*.md
var CommandsFS embed.FS

//go:embed skills
var SkillsFS embed.FS

//go:embed harnesses
var HarnessesFS embed.FS
