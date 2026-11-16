package crawler

import (
	"regexp"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/action"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
)

// spidering.deny_click_extra reaches the in-page URL primers and the POST-form
// enumeration, not only clicks: an RoE term keeps the crawl from fetching or
// submitting it with the browser's credentials.
func TestDenyClickExtraWidensPrimerAndFormFilters(t *testing.T) {
	extra := regexp.MustCompile("(?i)redeem")
	urls := []string{"https://a.test/voucher/redeem", "https://a.test/account/delete", "https://a.test/products"}
	if got := filterDestructiveURLs(urls, extra); len(got) != 1 || got[0] != "https://a.test/products" {
		t.Errorf("with extra: kept %v, want only /products", got)
	}
	if got := filterDestructiveURLs(urls, nil); len(got) != 2 {
		t.Errorf("without extra: kept %v, want /voucher/redeem and /products", got)
	}

	cfg, err := config.New("https://a.test/")
	if err != nil {
		t.Fatal(err)
	}
	c := &Crawler{config: cfg}
	if c.postFormsScript() != enumeratePostFormsScript {
		t.Error("with no extra the shared script is used")
	}
	cfg.DenyClickExtra = "(?:redeem)"
	c2 := &Crawler{config: cfg, extractor: action.NewCandidateElementExtractor(cfg)}
	if s := c2.postFormsScript(); !strings.Contains(s, "|(?:redeem)/i") || strings.Contains(s, "__DESTRUCTIVE_RE__") {
		t.Error("the POST-form filter must carry the extra terms")
	}
	if re := c2.extractor.DenyClickExtra(); re == nil || !re.MatchString("/REDEEM") {
		t.Error("the primers' extra pattern must be the click guard's, compiled case-insensitively")
	}

	// An invalid extra disables it for the primers exactly as for clicks.
	bad, err := config.New("https://a.test/")
	if err != nil {
		t.Fatal(err)
	}
	bad.DenyClickExtra = "(unclosed"
	if re := action.NewCandidateElementExtractor(bad).DenyClickExtra(); re != nil {
		t.Error("an invalid extra must compile to nil")
	}
}
