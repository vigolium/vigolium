package runner

import (
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/spitolas"
	"github.com/vigolium/vigolium/pkg/types"
)

func TestResolveBrowserPolicy_DefaultsMatchPackageDefault(t *testing.T) {
	// quick is the intensity whose login default is off, so the resolved policy
	// must be exactly the package default there.
	rp := resolveBrowserPolicy(*config.DefaultSpideringConfig(), "quick")
	if rp.policy != spitolas.DefaultInteractionPolicy() {
		t.Errorf("policy = %+v, want %+v", rp.policy, spitolas.DefaultInteractionPolicy())
	}
	if len(rp.sources) != 0 || len(rp.conflicts) != 0 {
		t.Errorf("default settings must report no sources/conflicts, got %v / %v", rp.sources, rp.conflicts)
	}

	// At the default (balanced) intensity only the login default differs, and the
	// report says where it came from.
	rp = resolveBrowserPolicy(*config.DefaultSpideringConfig(), "")
	want := spitolas.DefaultInteractionPolicy()
	want.LoginAttempts = true
	if rp.policy != want {
		t.Errorf("balanced policy = %+v, want %+v", rp.policy, want)
	}
	if rp.sources["login_attempts"] != policySourceIntensity {
		t.Errorf("login source = %q, want intensity", rp.sources["login_attempts"])
	}
}

func TestResolveBrowserPolicy_LegacyNoForms(t *testing.T) {
	sp := *config.DefaultSpideringConfig()
	sp.NoForms = true
	rp := resolveBrowserPolicy(sp, "quick")
	if rp.policy.EditFields || rp.policy.SubmitForms {
		t.Errorf("no_forms must turn edits and submits off, got %+v", rp.policy)
	}
	if len(rp.conflicts) != 0 {
		t.Errorf("no conflict expected, got %v", rp.conflicts)
	}
	if rp.sources["edit_fields"] != policySourceNoForms || rp.sources["submit_forms"] != policySourceNoForms {
		t.Errorf("sources = %v, want no_forms for both form categories", rp.sources)
	}
	if rp.policy.UploadFiles || rp.sources["upload_files"] != policySourceEditFields {
		t.Errorf("no_forms must withdraw the upload default (source edit_fields), got upload=%v source=%q",
			rp.policy.UploadFiles, rp.sources["upload_files"])
	}
}

func TestResolveBrowserPolicy_Uploads(t *testing.T) {
	// On by default, individually deniable.
	if rp := resolveBrowserPolicy(*config.DefaultSpideringConfig(), "quick"); !rp.policy.UploadFiles {
		t.Error("upload_files must default to on")
	}
	sp := *config.DefaultSpideringConfig()
	sp.Interaction.UploadFiles = boolPtr(false)
	rp := resolveBrowserPolicy(sp, "quick")
	if rp.policy.UploadFiles || !rp.policy.EditFields || rp.sources["upload_files"] != policySourceConfig {
		t.Errorf("upload_files=false: got %+v sources %v", rp.policy, rp.sources)
	}

	// An explicit allow cannot outlive denied edits, and the conflict is named.
	sp = *config.DefaultSpideringConfig()
	sp.Interaction.EditFields = boolPtr(false)
	sp.Interaction.UploadFiles = boolPtr(true)
	rp = resolveBrowserPolicy(sp, "quick")
	if rp.policy.UploadFiles {
		t.Error("upload_files=true with edit_fields=false must not report uploads on")
	}
	if len(rp.conflicts) != 1 || !strings.Contains(rp.conflicts[0], "upload_files") {
		t.Errorf("want one conflict naming upload_files, got %v", rp.conflicts)
	}
}

func TestResolveBrowserPolicy_ExplicitBeatsNoForms(t *testing.T) {
	sp := *config.DefaultSpideringConfig()
	sp.NoForms = true
	sp.Interaction.SubmitForms = boolPtr(true)
	rp := resolveBrowserPolicy(sp, "quick")
	if !rp.policy.SubmitForms {
		t.Error("explicit submit_forms=true must win over no_forms")
	}
	if rp.policy.EditFields {
		t.Error("edit_fields was not set explicitly, so no_forms still turns it off")
	}
	if len(rp.conflicts) != 1 || !strings.Contains(rp.conflicts[0], "submit_forms") {
		t.Errorf("want exactly one conflict naming submit_forms, got %v", rp.conflicts)
	}
}

func TestResolveBrowserPolicy_ExplicitKeys(t *testing.T) {
	sp := *config.DefaultSpideringConfig()
	sp.Interaction = config.SpideringInteractionConfig{
		SubmitForms:   boolPtr(false),
		UploadFiles:   boolPtr(false),
		DownloadFiles: boolPtr(true),
		Dialogs:       "accept-all",
	}
	rp := resolveBrowserPolicy(sp, "quick")
	if !rp.policy.EditFields || rp.policy.SubmitForms || rp.policy.UploadFiles || !rp.policy.DownloadFiles {
		t.Errorf("explicit keys not applied: %+v", rp.policy)
	}
	if rp.policy.DialogResponse != spitolas.DialogAcceptAll {
		t.Errorf("dialogs = %q, want accept-all", rp.policy.DialogResponse)
	}
}

// TestResolveAccountActions is the intensity × config matrix. The regression the
// resolver exists for: deep + register_account=false must not register.
func TestResolveAccountActions(t *testing.T) {
	type want struct{ register, login, full bool }
	configs := []struct {
		name string
		in   config.SpideringInteractionConfig
	}{
		{"unset", config.SpideringInteractionConfig{}},
		{"register=false", config.SpideringInteractionConfig{RegisterAccount: boolPtr(false)}},
		{"register=true", config.SpideringInteractionConfig{RegisterAccount: boolPtr(true)}},
		{"login=false", config.SpideringInteractionConfig{LoginAttempts: boolPtr(false)}},
	}
	expect := map[string]map[string]want{
		"quick": {
			"unset":          {false, false, false},
			"register=false": {false, false, false},
			"register=true":  {true, false, false},
			"login=false":    {false, false, false},
		},
		"balanced": {
			"unset":          {false, true, false},
			"register=false": {false, true, false},
			"register=true":  {true, true, false},
			"login=false":    {false, false, false},
		},
		"deep": {
			"unset":          {false, true, true},
			"register=false": {false, true, true},
			"register=true":  {true, true, true},
			"login=false":    {false, false, true},
		},
	}
	for intensity, row := range expect {
		for _, c := range configs {
			sp := *config.DefaultSpideringConfig()
			sp.Interaction = c.in
			a := resolveAccountActions(sp, intensity)
			got := want{a.register, a.login, a.fullList}
			if got != row[c.name] {
				t.Errorf("%s / %s: got %+v, want %+v", intensity, c.name, got, row[c.name])
			}
		}
	}

	// Named explicitly: the bug was `SelfRegister || intensity == "deep"`.
	sp := *config.DefaultSpideringConfig()
	sp.Interaction.RegisterAccount = boolPtr(false)
	if resolveAccountActions(sp, "deep").register {
		t.Fatal("deep + register_account=false registered an account")
	}
	// And an explicit allow survives quick.
	sp.Interaction = config.SpideringInteractionConfig{LoginAttempts: boolPtr(true)}
	if a := resolveAccountActions(sp, "quick"); !a.login || a.fullList {
		t.Errorf("quick + login_attempts=true: got login=%v full=%v, want login on with the minimal list", a.login, a.fullList)
	}
}

func TestResolveAccountActions_LegacySelfRegister(t *testing.T) {
	sp := *config.DefaultSpideringConfig()
	sp.SelfRegister = true
	a := resolveAccountActions(sp, "quick")
	if !a.register || a.registerSource != policySourceSelfRegister || len(a.conflicts) != 0 {
		t.Errorf("self_register=true: got %+v", a)
	}

	sp.Interaction.RegisterAccount = boolPtr(false)
	a = resolveAccountActions(sp, "deep")
	if a.register || a.registerSource != policySourceConfig {
		t.Errorf("explicit register_account=false must win over self_register, got %+v", a)
	}
	if len(a.conflicts) != 1 {
		t.Errorf("want one conflict, got %v", a.conflicts)
	}
}

func TestBrowserPolicyDetail(t *testing.T) {
	sp := *config.DefaultSpideringConfig()
	sp.Interaction.RegisterAccount = boolPtr(false)
	got := resolveBrowserPolicy(sp, "deep").detail()
	want := "edit_fields=on, submit_forms=on, upload_files=on, download_files=off, " +
		"register_account=off (config), login_attempts=on (intensity), dialogs=record-dismiss"
	if got != want {
		t.Errorf("detail =\n  %s\nwant\n  %s", got, want)
	}
}

// TestPolicyCategoriesDriftGuard pins the three tables that must agree: the
// spitolas category names, the keys Fields() reports, and the YAML keys of the
// spidering.interaction section (with "dialogs" the one non-boolean key).
func TestPolicyCategoriesDriftGuard(t *testing.T) {
	cats := slices.Clone(spitolas.PolicyCategories)
	sort.Strings(cats)

	fieldKeys := make([]string, 0)
	for k := range spitolas.DefaultInteractionPolicy().Fields() {
		fieldKeys = append(fieldKeys, k)
	}
	sort.Strings(fieldKeys)
	if !reflect.DeepEqual(cats, fieldKeys) {
		t.Errorf("Fields() keys %v != PolicyCategories %v", fieldKeys, cats)
	}

	var yamlKeys []string
	rt := reflect.TypeOf(config.SpideringInteractionConfig{})
	for i := 0; i < rt.NumField(); i++ {
		name, _, _ := strings.Cut(rt.Field(i).Tag.Get("yaml"), ",")
		if name == "deny_click_pattern" {
			continue // a click guard (SAFE-9), not a permission category
		}
		yamlKeys = append(yamlKeys, name)
	}
	sort.Strings(yamlKeys)
	if !reflect.DeepEqual(cats, yamlKeys) {
		t.Errorf("spidering.interaction YAML keys %v != PolicyCategories %v", yamlKeys, cats)
	}

	dialogs := make([]string, 0, len(spitolas.DialogPolicies))
	for _, d := range spitolas.DialogPolicies {
		dialogs = append(dialogs, string(d))
	}
	if !reflect.DeepEqual(dialogs, config.SpideringDialogPolicies) {
		t.Errorf("config.SpideringDialogPolicies %v != spitolas.DialogPolicies %v", config.SpideringDialogPolicies, dialogs)
	}
}

func TestBuildSpiderConfig_CarriesPolicy(t *testing.T) {
	sp := *config.DefaultSpideringConfig()
	sp.SelfRegister = true
	sp.Interaction.LoginAttempts = boolPtr(false)
	r := &Runner{options: &types.Options{Intensity: "deep"}}
	cfg := r.buildSpiderConfig("https://example.com/", sp, 0, &phaseInfra{})
	if cfg.Policy == nil {
		t.Fatal("buildSpiderConfig must set an explicit Policy")
	}
	if !cfg.Policy.RegisterAccount || cfg.Policy.LoginAttempts {
		t.Errorf("policy = %+v, want register on, login off", *cfg.Policy)
	}
	// The legacy switches mirror the policy, so a reader of either agrees.
	if cfg.SelfRegister != cfg.Policy.RegisterAccount || cfg.LoginCredentialAttempts != cfg.Policy.LoginAttempts {
		t.Errorf("legacy switches diverge from policy: self_register=%v login=%v", cfg.SelfRegister, cfg.LoginCredentialAttempts)
	}
	if cfg.EffectivePolicy() != *cfg.Policy {
		t.Error("EffectivePolicy must return the explicit policy")
	}
}

func TestResolveBrowserCompat(t *testing.T) {
	if got := resolveBrowserCompat(*config.DefaultSpideringConfig()); got != spitolas.DefaultBrowserCompat() {
		t.Errorf("default compat = %+v, want %+v", got, spitolas.DefaultBrowserCompat())
	}

	sp := *config.DefaultSpideringConfig()
	sp.BrowserCompat.IgnoreTLSErrors = boolPtr(false)
	sp.BrowserCompat.AllowInsecureContent = boolPtr(true)
	got := resolveBrowserCompat(sp)
	if got.IgnoreTLSErrors || !got.AllowInsecureContent || got.NoSandbox || got.DisableWebSecurity {
		t.Errorf("explicit keys not applied: %+v", got)
	}

	// --browser-insecure turns on all four.
	sp = *config.DefaultSpideringConfig()
	sp.BrowserCompat.SetAll(true)
	if got := resolveBrowserCompat(sp); got != spitolas.InsecureBrowserCompat() {
		t.Errorf("SetAll(true) compat = %+v, want %+v", got, spitolas.InsecureBrowserCompat())
	}
}

func TestSecurityDetail(t *testing.T) {
	got := securityDetail(spitolas.BrowserSecurity{BrowserCompat: spitolas.DefaultBrowserCompat()})
	want := "sandbox=on, tls=ignore-errors, mixed_content=block, web_security=on"
	if got != want {
		t.Errorf("default detail = %q, want %q", got, want)
	}

	forced := spitolas.BrowserSecurity{
		BrowserCompat:    spitolas.BrowserCompat{NoSandbox: true},
		SandboxForcedOff: true,
		SandboxReason:    "running as root",
	}
	got = securityDetail(forced)
	want = "sandbox=off (running as root), tls=verify, mixed_content=block, web_security=on"
	if got != want {
		t.Errorf("forced detail = %q, want %q", got, want)
	}
}

func TestBuildSpiderConfig_CarriesCompat(t *testing.T) {
	sp := *config.DefaultSpideringConfig()
	sp.BrowserCompat.SetAll(true)
	r := &Runner{options: &types.Options{}}
	cfg := r.buildSpiderConfig("https://example.com/", sp, 0, &phaseInfra{})
	if cfg.BrowserCompat == nil || *cfg.BrowserCompat != spitolas.InsecureBrowserCompat() {
		t.Errorf("BrowserCompat = %v, want the insecure posture", cfg.BrowserCompat)
	}
}

func TestBuildSpiderConfig_CarriesIdentityEmailDomain(t *testing.T) {
	sp := *config.DefaultSpideringConfig()
	sp.IdentityEmailDomain = "qa.example.net"
	r := &Runner{options: &types.Options{}}
	if cfg := r.buildSpiderConfig("https://example.com/", sp, 0, &phaseInfra{}); cfg.IdentityEmailDomain != "qa.example.net" {
		t.Errorf("IdentityEmailDomain = %q, want qa.example.net", cfg.IdentityEmailDomain)
	}
}

func TestBuildSpiderConfig_CarriesRequireAuth(t *testing.T) {
	sp := *config.DefaultSpideringConfig()
	r := &Runner{options: &types.Options{}}
	if cfg := r.buildSpiderConfig("https://example.com/", sp, 0, &phaseInfra{}); cfg.RequireAuth {
		t.Error("RequireAuth defaults on")
	}
	sp.RequireAuth = true
	if cfg := r.buildSpiderConfig("https://example.com/", sp, 0, &phaseInfra{}); !cfg.RequireAuth {
		t.Error("spidering.require_auth not carried into the crawl config")
	}
}

func TestBuildSpiderConfig_CarriesMaxCaptureBodyBytes(t *testing.T) {
	sp := *config.DefaultSpideringConfig()
	sp.MaxCaptureBodyBytes = 4 << 20
	r := &Runner{options: &types.Options{}}
	if cfg := r.buildSpiderConfig("https://example.com/", sp, 0, &phaseInfra{}); cfg.MaxCaptureBodyBytes != 4<<20 {
		t.Errorf("MaxCaptureBodyBytes = %d, want %d", cfg.MaxCaptureBodyBytes, 4<<20)
	}
}

// TestResolveBrowserPolicy_DeniedSubmitsWithdrawLoginDefault: credential
// attempts are submissions, so --no-forms withdraws the intensity default; an
// explicit login_attempts key still authorizes them.
func TestResolveBrowserPolicy_DeniedSubmitsWithdrawLoginDefault(t *testing.T) {
	sp := *config.DefaultSpideringConfig()
	sp.NoForms = true
	rp := resolveBrowserPolicy(sp, "deep")
	if rp.policy.LoginAttempts {
		t.Error("no_forms at deep must not leave the intensity login default on")
	}
	if rp.sources["login_attempts"] != policySourceSubmitForms {
		t.Errorf("login source = %q, want %q", rp.sources["login_attempts"], policySourceSubmitForms)
	}
	if !rp.fullList {
		t.Error("the list size still follows intensity")
	}

	sp.Interaction.LoginAttempts = boolPtr(true)
	if rp := resolveBrowserPolicy(sp, "deep"); !rp.policy.LoginAttempts {
		t.Error("an explicit login_attempts=true must survive denied submits")
	}
}
