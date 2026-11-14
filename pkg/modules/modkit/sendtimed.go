package modkit

import (
	"time"

	httputil "github.com/projectdiscovery/utils/http"
	vighttp "github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// SendTimed sends one timing-oracle probe and returns the latency the
// requester measured — from after the rate token and the host slot to the end
// of the response — instead of wall-clock time around Execute (MISS-14). At
// --rate-limit 5 the token wait alone exceeded a 2-second sleep payload, so a
// module that wrapped Execute in time.Since timed its own queue.
//
// It forces the options every timing probe needs whatever the caller passed:
//   - NoClustering: a re-sent identical probe must really re-execute, never be
//     answered from the 500ms request cache in ~0ms;
//   - NoRedirects: a followed hop adds a second server's latency;
//   - IgnoreTimeoutTracking: a sleep payload that times out says nothing about
//     host health and must not trip the breaker;
//   - NoRetry: a retried sleep payload doubles the server-side delay and the
//     measured attempt is not the one that slept.
//
// On error elapsed is the failed attempt's send-to-failure time (0 if the
// request was refused before it was sent).
func SendTimed(client *vighttp.Requester, req *httpmsg.HttpRequestResponse, opts vighttp.Options) (*httputil.ResponseChain, time.Duration, error) {
	opts.NoClustering = true
	opts.NoRedirects = true
	opts.IgnoreTimeoutTracking = true
	opts.NoRetry = true
	return client.Execute(req, opts)
}
