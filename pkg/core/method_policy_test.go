package core

import (
	"testing"

	"github.com/vigolium/vigolium/pkg/core/services"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/types"
)

// SAFE-8: a record whose method the traffic policy refuses is kept out of the
// active stage and counted as a method_policy skip.
func TestMethodPolicyAllows(t *testing.T) {
	opts := types.DefaultOptions()
	opts.TrafficPolicy = types.NewTrafficPolicy([]string{"GET", "HEAD"})
	e := &Executor{cfg: ExecutorConfig{Services: &services.Services{Options: opts}}}

	del, err := httpmsg.ParseRawRequest("DELETE /items/1 HTTP/1.1\r\nHost: a.test\r\n\r\n")
	if err != nil {
		t.Fatal(err)
	}
	get, _ := httpmsg.ParseRawRequest("GET /items/1 HTTP/1.1\r\nHost: a.test\r\n\r\n")
	if e.methodPolicyAllows(del) {
		t.Error("DELETE allowed under a read-only policy")
	}
	if !e.methodPolicyAllows(get) {
		t.Error("GET refused under a read-only policy")
	}
	if n := e.MethodPolicySkips(); n != 1 {
		t.Errorf("method_policy skips = %d, want 1", n)
	}
	open := &Executor{cfg: ExecutorConfig{Services: &services.Services{Options: types.DefaultOptions()}}}
	if !open.methodPolicyAllows(del) {
		t.Error("no policy must allow DELETE")
	}
}
