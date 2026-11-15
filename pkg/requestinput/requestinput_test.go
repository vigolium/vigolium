package requestinput

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/portsweep"
	"github.com/vigolium/vigolium/pkg/requestscheme"
)

func plainHTTP(_ context.Context, host, port, rest string, _ portsweep.SchemeOptions) portsweep.SchemeResolution {
	return portsweep.SchemeResolution{URL: "http://" + host + ":" + port + rest, Reachable: true, Scheme: "http"}
}

func TestNormalize(t *testing.T) {
	for name, tc := range map[string]struct{ in, parsed, send string }{
		"terminated":         {"GET / HTTP/1.1\r\nHost: h\r\n\r\n", "GET / HTTP/1.1\r\nHost: h", "GET / HTTP/1.1\r\nHost: h\r\n\r\n"},
		"stripped":           {"GET / HTTP/1.1\r\nHost: h", "GET / HTTP/1.1\r\nHost: h", "GET / HTTP/1.1\r\nHost: h\r\n\r\n"},
		"leading blank":      {"\n\nGET / HTTP/1.1\nHost: h\n", "GET / HTTP/1.1\nHost: h", "GET / HTTP/1.1\nHost: h\r\n\r\n"},
		"body kept verbatim": {"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 4\r\n\r\na=1 ", "POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 4\r\n\r\na=1 ", "POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 4\r\n\r\na=1 "},
	} {
		p, s := Normalize(tc.in)
		if p != tc.parsed || s != tc.send {
			t.Errorf("%s: Normalize = %q, %q; want %q, %q", name, p, s, tc.parsed, tc.send)
		}
	}
}

func TestParseScheme(t *testing.T) {
	ctx := context.Background()
	raw := "GET /r?id=1 HTTP/1.1\r\nHost: 127.0.0.1:18971"

	res, err := Parse(ctx, raw, Options{Resolver: plainHTTP})
	if err != nil {
		t.Fatal(err)
	}
	if res.Request.Target() != "http://127.0.0.1:18971" && !strings.HasPrefix(res.Request.Target(), "http://127.0.0.1:18971") {
		t.Errorf("probed target = %q, want plain http", res.Request.Target())
	}
	if res.SchemeSource != requestscheme.SourceProbe || !strings.HasSuffix(res.Raw, "\r\n\r\n") {
		t.Errorf("source %q raw %q", res.SchemeSource, res.Raw)
	}

	res, err = Parse(ctx, raw, Options{Target: "http://10.0.0.5:8080", Resolver: func(context.Context, string, string, string, portsweep.SchemeOptions) portsweep.SchemeResolution {
		t.Fatal("a -t override is never probed")
		return portsweep.SchemeResolution{}
	}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(res.Request.Target(), "http://10.0.0.5:8080") || res.SchemeSource != requestscheme.SourceExplicit {
		t.Errorf("-t target = %q (%s)", res.Request.Target(), res.SchemeSource)
	}

	res, _ = Parse(ctx, raw, Options{NoProbe: true})
	if res.SchemeSource != requestscheme.SourceDefault || !strings.HasPrefix(res.Request.Target(), "https://") {
		t.Errorf("no probe = %q (%s)", res.Request.Target(), res.SchemeSource)
	}

	if _, err := Parse(ctx, "  \n", Options{}); !errors.Is(err, ErrEmpty) {
		t.Errorf("empty input: %v", err)
	}
}
