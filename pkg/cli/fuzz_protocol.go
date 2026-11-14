package cli

import (
	"context"
	gohttp "net/http"
	"net/url"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/pkg/bulkhttp"
	"github.com/vigolium/vigolium/pkg/fuzz"
)

// fuzzMultiplexedConcurrency is fuzz's default worker count when the target is
// pinned to HTTP/2 or HTTP/3 and -c was not given. Ten workers was sized for
// HTTP/1.1, where each one holds its own connection; multiplexed, fifty
// requests in flight share one or two connections and stay under the common
// 100-stream server limit.
const fuzzMultiplexedConcurrency = 50

// fuzzWire is a run's resolved wire protocol and the worker count it implies,
// reported on the stderr run line and in the -j summary's pace. The zero value
// is "not resolved" (--dry-run): the flag's concurrency, no protocol.
type fuzzWire struct {
	proto bulkhttp.Protocol
	note  string // why the run is not on a multiplexed protocol, when it matters
	// concurrency is the effective worker count; 0 = the -c flag's value.
	concurrency int
}

// resolveFuzzProtocol picks the run's protocol mode and builds its client. A
// job HTTP/2 or HTTP/3 would not deliver faithfully (fuzz.MultiplexBlocker)
// stays on HTTP/1.1, or fails under --http3-only. The target's protocol is
// then decided without an HTTP request (bulkhttp.Transport.Prepare), so the
// baseline and every case go out on the same one, and the default worker
// count rises when that protocol is multiplexed. bulk is nil on a plain
// HTTP/1.1 client; the caller closes it.
func resolveFuzzProtocol(cmd *cobra.Command, src *replaySource, positions []fuzz.Position, cases fuzz.CasePlan, sendViaBurp bool, cookies gohttp.CookieJar) (client *gohttp.Client, bulk *bulkhttp.Transport, wire fuzzWire, err error) {
	mode, err := fuzzHTTPVersionSetting()
	if err != nil {
		return nil, nil, wire, err
	}
	if mode != bulkhttp.ModeHTTP1 && !sendViaBurp {
		if blocker := fuzz.MultiplexBlockerPlan(src.BaselineRequest, positions, cases); blocker != "" {
			if mode == bulkhttp.ModeHTTP3 {
				return nil, nil, wire, usageErrorf("--http3-only: this job must be sent as HTTP/1.1: %s", blocker)
			}
			mode = bulkhttp.ModeHTTP1
			wire.note = "HTTP/1.1 because " + blocker
		}
	}
	client, bulk, err = buildFuzzClient(cookies, mode)
	if err != nil {
		return nil, nil, wire, err
	}
	switch {
	case sendViaBurp:
		// Burp's engine sends every request; its protocol is --http-mode.
	case bulk == nil:
		wire.proto = bulkhttp.ProtoHTTP1
	default:
		target, perr := url.Parse(fuzzTargetLabel(src))
		if perr != nil {
			bulk.Close()
			return nil, nil, wire, perr
		}
		ctx := cmd.Context()
		if ctx == nil {
			ctx = context.Background()
		}
		if wire.proto, err = bulk.Prepare(ctx, target); err != nil {
			bulk.Close()
			return nil, nil, wire, err
		}
	}
	if wire.proto.Multiplexed() && !cmd.Flags().Changed("concurrency") {
		wire.concurrency = fuzzMultiplexedConcurrency
	}
	return client, bulk, wire, nil
}
