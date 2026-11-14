package runner

import (
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/spitolas"
	"github.com/vigolium/vigolium/pkg/types"
)

// Policy value sources, reported next to a category when its value did not come
// from spitolas.DefaultInteractionPolicy.
const (
	policySourceConfig       = "config"        // spidering.interaction.<key>
	policySourceNoForms      = "no_forms"      // legacy spidering.no_forms / --no-forms
	policySourceSelfRegister = "self_register" // legacy spidering.self_register
	policySourceIntensity    = "intensity"     // the intensity default (login attempts only)
	policySourceSubmitForms  = "submit_forms"  // login default withdrawn because submits are denied
	policySourceEditFields   = "edit_fields"   // upload withdrawn because field edits are denied
	policySourceMethods      = "scope.methods" // withdrawn by the traffic policy
)

// applyTrafficPolicy withdraws what the scan's traffic policy forbids:
// a read-only scope.methods means no form submission, account creation,
// crawler login attempts or uploads, whatever spidering.interaction says.
func (rp *resolvedBrowserPolicy) applyTrafficPolicy(tp *types.TrafficPolicy) {
	if tp == nil {
		return
	}
	withdraw := func(category string, dst *bool) {
		if *dst {
			*dst = false
			rp.sources[category] = policySourceMethods
		}
	}
	if !tp.AllowsSubmitForms() {
		withdraw("submit_forms", &rp.policy.SubmitForms)
		withdraw("register_account", &rp.policy.RegisterAccount)
	}
	if !tp.AllowsLoginAttempts() {
		withdraw("login_attempts", &rp.policy.LoginAttempts)
	}
	if !tp.AllowsUploads() {
		withdraw("upload_files", &rp.policy.UploadFiles)
	}
}

// resolvedBrowserPolicy is a resolved interaction policy plus what the spidering
// report needs to explain it.
type resolvedBrowserPolicy struct {
	policy spitolas.InteractionPolicy
	// fullList sizes the default-credential list; it is not a permission.
	fullList bool
	// sources maps a PolicyCategories name to where its value came from; a
	// category absent from the map holds its default.
	sources map[string]string
	// conflicts names each explicit interaction key that overrode a legacy key
	// saying the opposite. Logged once per phase.
	conflicts []string
}

// resolveBrowserPolicy resolves what the browser crawl may change. Precedence
// global → project → profile → CLI is already folded into sp by
// LoadSettingsWithProject / ApplyProfile and the CLI overrides in pkg/cli, so
// the only job here is: an explicit spidering.interaction value wins, else the
// legacy no_forms / self_register keys, else the default. Intensity is consulted
// for login attempts only, and only as a default — see resolveAccountActions.
//
// It takes the spidering section by value, not *Settings, because both browser
// phases build from a local copy carrying the headed override.
func resolveBrowserPolicy(sp config.SpideringConfig, intensity string) resolvedBrowserPolicy {
	rp := resolvedBrowserPolicy{
		policy:  spitolas.DefaultInteractionPolicy(),
		sources: map[string]string{},
	}
	in := sp.Interaction

	// Forms: --no-forms / no_forms turns both edits and submits off unless an
	// explicit interaction key says otherwise.
	applyFormKey := func(category string, dst *bool, explicit *bool) {
		if sp.NoForms {
			*dst = false
			rp.sources[category] = policySourceNoForms
		}
		if explicit == nil {
			return
		}
		if sp.NoForms && *explicit {
			rp.conflicts = append(rp.conflicts, fmt.Sprintf("spidering.interaction.%s=true overrides spidering.no_forms=true", category))
		}
		*dst = *explicit
		rp.sources[category] = policySourceConfig
	}
	applyFormKey("edit_fields", &rp.policy.EditFields, in.EditFields)
	applyFormKey("submit_forms", &rp.policy.SubmitForms, in.SubmitForms)

	if in.UploadFiles != nil {
		rp.policy.UploadFiles = *in.UploadFiles
		rp.sources["upload_files"] = policySourceConfig
	}
	// Attaching a file is a field edit: with edits denied nothing fills a file
	// input, so the report must not claim uploads are on.
	if !rp.policy.EditFields && rp.policy.UploadFiles {
		if in.UploadFiles != nil {
			rp.conflicts = append(rp.conflicts, "spidering.interaction.upload_files=true has no effect while edit_fields is off")
		}
		rp.policy.UploadFiles = false
		rp.sources["upload_files"] = policySourceEditFields
	}
	if in.DownloadFiles != nil {
		rp.policy.DownloadFiles = *in.DownloadFiles
		rp.sources["download_files"] = policySourceConfig
	}

	acct := resolveAccountActions(sp, intensity)
	// Credential attempts are form submissions. When submits are denied, the
	// intensity default must not quietly keep them on; only an explicit
	// login_attempts key (its own authorization) does.
	if !rp.policy.SubmitForms && acct.login && acct.loginSource == policySourceIntensity {
		acct.login = false
		acct.loginSource = policySourceSubmitForms
	}
	rp.policy.RegisterAccount = acct.register
	rp.policy.LoginAttempts = acct.login
	rp.fullList = acct.fullList
	if acct.registerSource != "" {
		rp.sources["register_account"] = acct.registerSource
	}
	if acct.loginSource != "" {
		rp.sources["login_attempts"] = acct.loginSource
	}
	rp.conflicts = append(rp.conflicts, acct.conflicts...)

	if in.Dialogs != "" {
		rp.policy.DialogResponse = spitolas.DialogPolicy(in.Dialogs)
		rp.sources["dialogs"] = policySourceConfig
	}
	return rp
}

// detail renders the policy for the spidering config detail line, one entry per
// spitolas.PolicyCategories name in table order so the report cannot drift from
// the categories the crawler enforces:
//
//	Policy: edit_fields=on, submit_forms=on, …, login_attempts=on (intensity), dialogs=record-dismiss
func (rp resolvedBrowserPolicy) detail() string {
	return renderFieldLine(spitolas.PolicyCategories, rp.policy.Fields(),
		func(name string) string { return rp.sources[name] })
}

// renderFieldLine renders a `name=value` report line from a Fields() map, one
// entry per name in order, so a line cannot drift from the table it describes.
// annotate supplies an optional parenthesised note per entry (empty for none);
// a nil annotate renders values alone. Bools render as on/off, which is how
// every switch in these reports reads; anything else goes through fmt.Sprint.
func renderFieldLine(order []string, fields map[string]any, annotate func(string) string) string {
	parts := make([]string, 0, len(order))
	for _, name := range order {
		var v string
		switch val := fields[name].(type) {
		case bool:
			v = "off"
			if val {
				v = "on"
			}
		default:
			v = fmt.Sprint(val)
		}
		entry := name + "=" + v
		if annotate != nil {
			if note := annotate(name); note != "" {
				entry += " (" + note + ")"
			}
		}
		parts = append(parts, entry)
	}
	return strings.Join(parts, ", ")
}

// resolveBrowserCompat applies spidering.browser_compat over the defaults. The
// sandbox's host-forced state is not decided here — the launcher owns it — and
// is folded in by spitolas.EffectiveBrowserSecurity for the report.
func resolveBrowserCompat(sp config.SpideringConfig) spitolas.BrowserCompat {
	c := spitolas.DefaultBrowserCompat()
	bc := sp.BrowserCompat
	c.NoSandbox = boolPtrOr(bc.NoSandbox, c.NoSandbox)
	c.IgnoreTLSErrors = boolPtrOr(bc.IgnoreTLSErrors, c.IgnoreTLSErrors)
	c.AllowInsecureContent = boolPtrOr(bc.AllowInsecureContent, c.AllowInsecureContent)
	c.DisableWebSecurity = boolPtrOr(bc.DisableWebSecurity, c.DisableWebSecurity)
	return c
}

// securityDetail renders the effective browser security posture for the
// spidering report, in spitolas.SecurityFieldOrder, naming the reason when the
// host forced the sandbox off:
//
//	sandbox=on, tls=ignore-errors, mixed_content=block, web_security=on
func securityDetail(s spitolas.BrowserSecurity) string {
	return renderFieldLine(spitolas.SecurityFieldOrder, s.Fields(), func(k string) string {
		if k == "sandbox" && s.SandboxForcedOff {
			return s.SandboxReason
		}
		return ""
	})
}
