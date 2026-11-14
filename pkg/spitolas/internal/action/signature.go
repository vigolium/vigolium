package action

import (
	"net/url"
	"regexp"
	"strings"
)

// signatureMABPolicy is the optional MAB extension that seeds a new arm from
// its signature's crawl-wide reward.
type signatureMABPolicy interface {
	AddActionWithSignature(stateID, actionID, sig string)
}

var sigDigitsRe = regexp.MustCompile(`\d+`)

// CandidateSignature is what makes two actions "the same kind" across
// states: tag, event type, normalised text (digits collapsed) and the link's
// path shape. Two "Next page" links on different listings share it; a
// "Delete" and an "Edit" button do not.
func CandidateSignature(c *CandidateElement) string {
	if c == nil {
		return ""
	}
	text := strings.ToLower(strings.Join(strings.Fields(c.Text), " "))
	if len(text) > 40 {
		text = text[:40]
	}
	text = sigDigitsRe.ReplaceAllString(text, "#")
	hrefShape := ""
	if c.Href != "" {
		if u, err := url.Parse(c.Href); err == nil {
			hrefShape = sigDigitsRe.ReplaceAllString(u.Path, "#")
		}
	}
	return c.TagName + "|" + string(c.EventType) + "|" + text + "|" + hrefShape
}
