// Package olium exposes the skills shipped as built-ins with the olium
// agent. The embedded FS is consumed by pkg/olium/skill's Loader; user
// skills in .agents/skills/, .claude/skills/, or ~/.vigolium/skills/
// take precedence on name collision.
package olium

import "embed"

//go:embed skills
var SkillsFS embed.FS

// SkillsPrefix is the relative path inside SkillsFS that the skill
// loader should scan. Kept as a constant so callers don't have to
// duplicate the string.
const SkillsPrefix = "skills"
