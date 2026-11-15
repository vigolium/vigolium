package http

import (
	"net/url"

	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/rawhttp"

	"github.com/vigolium/vigolium/pkg/http/proxyenv"
)

// rawClientSet holds the raw clients a Requester sends through. rawhttp dials
// through the proxy its client was built with, not a per-call one, so a proxy
// chosen per request (by scheme, minus NO_PROXY) needs a client per proxy plus
// a direct one.
type rawClientSet struct {
	choice  proxyenv.Choice
	direct  *rawhttp.Client
	proxied map[string]*rawhttp.Client // keyed by proxy URL
}

func newRawClientSet(base rawhttp.Options, dialer *fastdialer.Dialer, choice proxyenv.Choice) *rawClientSet {
	set := &rawClientSet{choice: choice, proxied: map[string]*rawhttp.Client{}}
	direct := base
	direct.FastDialer = dialer
	set.direct = rawhttp.NewClient(&direct)
	for _, r := range choice.Proxies() {
		opts := base
		opts.Proxy = r.URL.String()
		set.proxied[r.URL.String()] = rawhttp.NewClient(&opts)
	}
	return set
}

// forURL returns the raw client a request to u goes through.
func (s *rawClientSet) forURL(u *url.URL) *rawhttp.Client {
	if s == nil {
		return nil
	}
	r := s.choice.For(u)
	if r == nil {
		return s.direct
	}
	if c, ok := s.proxied[r.URL.String()]; ok {
		return c
	}
	return s.direct
}
