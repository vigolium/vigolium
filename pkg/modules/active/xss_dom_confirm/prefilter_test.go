package xss_dom_confirm

import "testing"

func TestPrefilterReflectionInBody(t *testing.T) {
	canary := "vig-x-deadbeefcafe"
	body := `<html><body><div>reflected: ` + canary + `</div></body></html>`
	pass, reason := passesPrefilter(body, canary)
	if !pass {
		t.Fatalf("expected reflection to pass; got pass=false")
	}
	if reason != ReasonReflectionInBody {
		t.Fatalf("reason = %q, want %q", reason, ReasonReflectionInBody)
	}
}

func TestPrefilterDomSourceSink(t *testing.T) {
	body := `<html><body>
<script>
  var x = location.hash;
  document.getElementById('out').innerHTML = x;
</script>
</body></html>`
	pass, reason := passesPrefilter(body, "vig-x-not-present")
	if !pass {
		t.Fatalf("expected source-sink coupling to pass")
	}
	if reason != ReasonDOMSourceSink {
		t.Fatalf("reason = %q, want %q", reason, ReasonDOMSourceSink)
	}
}

func TestPrefilterRejectsCleanResponse(t *testing.T) {
	body := `<html><body><h1>nothing fishy here</h1></body></html>`
	pass, _ := passesPrefilter(body, "vig-x-not-present")
	if pass {
		t.Fatalf("expected clean response to fail pre-filter")
	}
}

func TestPrefilterRejectsSourceWithoutSink(t *testing.T) {
	// A source mention alone (no sink in same script block) should not
	// trigger a browser probe.
	body := `<html><body>
<script>
  var x = location.hash;
  console.log("logging", x);
</script>
</body></html>`
	pass, _ := passesPrefilter(body, "vig-x-not-present")
	if pass {
		t.Fatalf("source without sink should not pass")
	}
}

func TestPrefilterRequiresSameScriptBlock(t *testing.T) {
	// Source in one block, sink in another — too weak to escalate.
	body := `<html><body>
<script>var x = location.hash;</script>
<p>some content</p>
<script>document.write("static");</script>
</body></html>`
	pass, _ := passesPrefilter(body, "vig-x-not-present")
	if pass {
		t.Fatalf("source and sink in different blocks should not pass")
	}
}
