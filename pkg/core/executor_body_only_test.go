package core

import (
	"context"
	"testing"

	"github.com/vigolium/vigolium/pkg/modules"
)

type bodyOnlyPassive struct{ trackingPassiveModule }

func (*bodyOnlyPassive) BodyOnly() bool { return true }

// A BodyOnlyPassive module runs once per distinct body: the same bundle served
// at three URLs is analysed once; an ordinary passive module still runs on
// every record.
func TestBodyOnlyPassiveRunsOncePerBody(t *testing.T) {
	bo := &bodyOnlyPassive{trackingPassiveModule{id: "body-only"}}
	plain := &trackingPassiveModule{id: "plain"}
	e := NewExecutor(ExecutorConfig{Workers: 1, SkipBaseline: true}, &sliceSource{}, nil,
		[]modules.PassiveModule{bo, plain})

	for _, p := range []string{"/a.js", "/b.js", "/c.js"} {
		item, _ := makeTestItem("bundle.test", p, "console.log('same bundle')")
		e.processItem(context.Background(), item)
	}
	other, _ := makeTestItem("bundle.test", "/d.js", "console.log('different')")
	e.processItem(context.Background(), other)

	if got := bo.called.Load(); got != 2 {
		t.Fatalf("body-only module ran %d times, want 2 (two distinct bodies)", got)
	}
	if got := plain.called.Load(); got != 4 {
		t.Fatalf("plain module ran %d times, want 4", got)
	}
}
