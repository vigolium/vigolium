package cli

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/vigolium/vigolium/pkg/diagnostics"
)

// doctorSkillFixKey is the --only token for the skill reinstall ("skills" is
// accepted too).
const doctorSkillFixKey = "skill"

// doctorSkillCheck builds the doctor `skill` check from the install views
// scanInstalledSkills returns: a warning when any install is stale or
// modified, ok when every install is current, and an ok "not installed" when
// none of the four locations holds a bundled skill (the skill is optional).
// version is the running binary's, for the message.
func doctorSkillCheck(views []skillInstalledView, version string) *diagnostics.CheckResult {
	var current, stale, modified int
	var details []string
	for _, v := range views {
		if v.Status == skillStatusMissing {
			continue
		}
		switch v.Status {
		case skillStatusCurrent:
			current++
		case skillStatusStale:
			stale++
		case skillStatusModified:
			modified++
		}
		installedBy := v.Version
		if installedBy == "" {
			installedBy = "unstamped"
		}
		details = append(details, fmt.Sprintf("%s: %s (%s %s, %s)", v.Path, v.Status, v.Agent, v.Scope, installedBy))
	}

	total := current + stale + modified
	if total == 0 {
		return &diagnostics.CheckResult{
			Status:  diagnostics.StatusOK,
			Message: "not installed (optional)",
			Details: []string{"searched ./.claude/skills, ~/.claude/skills, ./.agents/skills, ~/.agents/skills"},
			Tip:     "teach your coding agent to drive vigolium: `vigolium skills install --agent claude`",
		}
	}
	if stale == 0 && modified == 0 {
		return &diagnostics.CheckResult{
			Status:  diagnostics.StatusOK,
			Message: fmt.Sprintf("current=%d, version=%s", current, version),
			Details: details,
		}
	}

	c := &diagnostics.CheckResult{
		Status:  diagnostics.StatusWarning,
		Message: fmt.Sprintf("current=%d, stale=%d, modified=%d, version=%s", current, stale, modified, version),
		Details: details,
	}
	var tips []string
	if stale > 0 {
		tips = append(tips, "stale copies predate this binary: `vigolium doctor --fix --only skill` reinstalls them")
	}
	if modified > 0 {
		tips = append(tips, "modified copies have local edits: `vigolium skills install --force` (with its --agent/--scope) discards them")
	}
	c.Tip = strings.Join(tips, "; ")
	return c
}

// attachDoctorSkillCheck fills report.Skill from the four install locations.
func attachDoctorSkillCheck(report *diagnostics.Report) {
	if report == nil {
		return
	}
	skills, err := loadBundledSkills()
	if err != nil {
		report.Skill = &diagnostics.CheckResult{Status: diagnostics.StatusWarning, Message: err.Error()}
		return
	}
	report.Skill = doctorSkillCheck(scanInstalledSkills(skills), Version)
}

// doctorSkillFixSelected reports whether --fix should touch skills: always
// without --only, otherwise only when --only names it.
func doctorSkillFixSelected(only []string) bool {
	if len(only) == 0 {
		return true
	}
	return slices.ContainsFunc(only, func(s string) bool {
		s = strings.ToLower(strings.TrimSpace(s))
		return s == doctorSkillFixKey || s == "skills"
	})
}

// doctorSkillStale reports whether any install location holds a stale copy,
// the one state doctor --fix repairs.
func doctorSkillStale() bool {
	skills, err := loadBundledSkills()
	if err != nil {
		return false
	}
	for _, loc := range skillInstallLocations() {
		for _, b := range skills {
			_, digest, _ := bundleContents(b)
			if inspectSkillInstall(filepath.Join(loc.Dir, b.Name), digest).Status == skillStatusStale {
				return true
			}
		}
	}
	return false
}

// fixStaleSkills reinstalls every stale install in place, as
// `skills install --force` would (pruning dropped files, backing up an
// unstamped copy). Modified installs are left alone: their edits are the
// user's. It returns one FixResult per stale install.
func fixStaleSkills(version, commit string) []diagnostics.FixResult {
	skills, err := loadBundledSkills()
	if err != nil {
		return []diagnostics.FixResult{{Key: doctorSkillFixKey, Label: "Agent skill", Message: err.Error()}}
	}
	now := time.Now()
	var results []diagnostics.FixResult
	for _, v := range scanInstalledSkills(skills) {
		if v.Status != skillStatusStale {
			continue
		}
		b, ok := findBundle(skills, v.Name)
		if !ok {
			continue
		}
		res := diagnostics.FixResult{Key: doctorSkillFixKey, Label: "Agent skill"}
		out, instErr := installSkillBundle(b, v.Path, true, version, commit, now)
		switch {
		case instErr != nil:
			res.Message = fmt.Sprintf("%s: %v", v.Path, instErr)
		default:
			res.Success = out.Installed
			res.Message = fmt.Sprintf("reinstalled %s at %s", b.Name, filepath.Dir(v.Path))
			if out.Backup != "" {
				res.Message += " (previous copy moved to " + out.Backup + ")"
			}
			if len(out.Pruned) > 0 {
				res.Message += fmt.Sprintf(" (removed %d dropped file(s))", len(out.Pruned))
			}
		}
		results = append(results, res)
	}
	return results
}
