package runner

import (
	"testing"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/types"
)

// A read-only traffic policy withdraws submits, signups, crawler
// logins and uploads from the browser crawl whatever spidering.interaction says.
func TestApplyTrafficPolicy_ReadOnlyWithdrawsInteractions(t *testing.T) {
	yes := true
	sp := config.SpideringConfig{}
	sp.Interaction.SubmitForms = &yes
	sp.Interaction.UploadFiles = &yes
	sp.Interaction.LoginAttempts = &yes
	rp := resolveBrowserPolicy(sp, "deep")
	rp.applyTrafficPolicy(types.NewTrafficPolicy([]string{"GET", "HEAD"}))
	if rp.policy.SubmitForms || rp.policy.UploadFiles || rp.policy.LoginAttempts || rp.policy.RegisterAccount {
		t.Errorf("read-only policy left interactions on: %+v", rp.policy)
	}
	if rp.sources["submit_forms"] != policySourceMethods {
		t.Errorf("submit_forms source = %q, want %q", rp.sources["submit_forms"], policySourceMethods)
	}

	rp2 := resolveBrowserPolicy(sp, "deep")
	rp2.applyTrafficPolicy(nil)
	if !rp2.policy.SubmitForms {
		t.Error("no policy must leave submits on")
	}
}

func TestAppendMissingTags(t *testing.T) {
	got := appendMissingTags([]string{"DOS"}, readOnlyExcludedTemplateTags...)
	if len(got) != 3 {
		t.Errorf("tags = %v, want dos kept once plus intrusive,fuzz", got)
	}
}
