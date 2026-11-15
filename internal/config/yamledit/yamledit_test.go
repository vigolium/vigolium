package yamledit

import (
	"strings"
	"testing"

	"github.com/vigolium/vigolium/public"
	"gopkg.in/yaml.v3"
)

func mustNode(t *testing.T, v any) *yaml.Node {
	t.Helper()
	n, err := Node(v)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func render(t *testing.T, d *Doc) string {
	t.Helper()
	out, err := d.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func renderSpliced(t *testing.T, d *Doc) string {
	t.Helper()
	out := render(t, d)
	if d.reencoded {
		t.Fatalf("expected a splice, got a full re-encode:\n%s", out)
	}
	return out
}

// changedLines returns the lines of b that differ from a, assuming the edit
// replaced lines in place (same count) — the common scalar case.
func diffLines(a, b string) []int {
	al, bl := strings.Split(a, "\n"), strings.Split(b, "\n")
	var out []int
	for i := 0; i < len(al) && i < len(bl); i++ {
		if al[i] != bl[i] {
			out = append(out, i+1)
		}
	}
	if len(al) != len(bl) {
		out = append(out, -1)
	}
	return out
}

const sample = `# head comment
server:
  # port comment
  port: 9002   # trailing
  host: "127.0.0.1"
  secret: ${MY_SECRET}

notify:
  enabled: false
  telegram:
    bot_token: ${TELEGRAM_BOT_TOKEN}
  severities:
    - high
    - critical

modules:
  active: [all]
# footer
`

func TestSetScalarInPlace(t *testing.T) {
	d, err := Parse([]byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Set([]string{"server", "port"}, mustNode(t, 9100)); err != nil {
		t.Fatal(err)
	}
	if err := d.Set([]string{"server", "host"}, mustNode(t, "0.0.0.0")); err != nil {
		t.Fatal(err)
	}
	if err := d.Set([]string{"notify", "enabled"}, mustNode(t, true)); err != nil {
		t.Fatal(err)
	}
	got := renderSpliced(t, d)
	want := strings.NewReplacer(
		"port: 9002   # trailing", "port: 9100   # trailing",
		`host: "127.0.0.1"`, `host: "0.0.0.0"`,
		"enabled: false", "enabled: true",
	).Replace(sample)
	if got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestSetInsertsMissingKeys(t *testing.T) {
	d, _ := Parse([]byte(sample))
	if err := d.Set([]string{"notify", "telegram", "chat_id"}, mustNode(t, "42")); err != nil {
		t.Fatal(err)
	}
	if err := d.Set([]string{"notify", "discord", "webhook_url"}, mustNode(t, "https://x")); err != nil {
		t.Fatal(err)
	}
	if err := d.Set([]string{"storage", "bucket"}, mustNode(t, "b")); err != nil {
		t.Fatal(err)
	}
	got := renderSpliced(t, d)
	for _, keep := range []string{"${MY_SECRET}", "${TELEGRAM_BOT_TOKEN}", "# head comment", "# port comment", "# trailing", "# footer"} {
		if !strings.Contains(got, keep) {
			t.Errorf("%q lost:\n%s", keep, got)
		}
	}
	if !strings.Contains(got, "    bot_token: ${TELEGRAM_BOT_TOKEN}\n    chat_id: \"42\"\n") {
		t.Errorf("chat_id not inserted under telegram:\n%s", got)
	}
	if !strings.Contains(got, "  discord:\n    webhook_url: https://x\n") {
		t.Errorf("discord not inserted:\n%s", got)
	}
	var v map[string]any
	if err := yaml.Unmarshal([]byte(got), &v); err != nil {
		t.Fatal(err)
	}
	if v["storage"].(map[string]any)["bucket"] != "b" {
		t.Errorf("storage.bucket = %v", v["storage"])
	}
}

func TestListEdits(t *testing.T) {
	d, _ := Parse([]byte(sample))
	n, err := d.AppendUnique([]string{"notify", "severities"}, mustNode(t, "medium"), mustNode(t, "high"))
	if err != nil || n != 1 {
		t.Fatalf("append = %d, %v", n, err)
	}
	if _, err := d.AppendUnique([]string{"modules", "active"}, mustNode(t, "xss")); err != nil {
		t.Fatal(err)
	}
	got := renderSpliced(t, d)
	if !strings.Contains(got, "    - critical\n    - medium\n\nmodules:") {
		t.Errorf("block append wrong:\n%s", got)
	}
	if !strings.Contains(got, "  active: [all, xss]\n# footer") {
		t.Errorf("flow append wrong:\n%s", got)
	}

	d, _ = Parse([]byte(got))
	if n, err := d.RemoveItems([]string{"notify", "severities"}, "high", "critical", "medium"); err != nil || n != 3 {
		t.Fatalf("remove = %d, %v", n, err)
	}
	got = renderSpliced(t, d)
	if !strings.Contains(got, "  severities: []\n") {
		t.Errorf("emptied list should be []:\n%s", got)
	}
}

func TestDeleteAndNullParent(t *testing.T) {
	src := "a:\n  b: 1\n  c: 2\nd:\ne: x\n"
	d, _ := Parse([]byte(src))
	if ok, err := d.Delete([]string{"a", "b"}); !ok || err != nil {
		t.Fatalf("delete = %v %v", ok, err)
	}
	if err := d.Set([]string{"d", "f"}, mustNode(t, 1)); err != nil {
		t.Fatal(err)
	}
	got := renderSpliced(t, d)
	if got != "a:\n  c: 2\nd:\n  f: 1\ne: x\n" {
		t.Fatalf("got:\n%s", got)
	}
}

func TestEmptyAndFlowDocuments(t *testing.T) {
	for _, src := range []string{"", "{}\n", "# only a comment\n"} {
		d, err := Parse([]byte(src))
		if err != nil {
			t.Fatalf("%q: %v", src, err)
		}
		if err := d.Set([]string{"scope", "host", "include"}, mustNode(t, []string{"a.example"})); err != nil {
			t.Fatal(err)
		}
		got := render(t, d)
		var v struct {
			Scope struct {
				Host struct {
					Include []string `yaml:"include"`
				} `yaml:"host"`
			} `yaml:"scope"`
		}
		if err := yaml.Unmarshal([]byte(got), &v); err != nil {
			t.Fatalf("%q -> %q: %v", src, got, err)
		}
		if len(v.Scope.Host.Include) != 1 {
			t.Fatalf("%q -> %q", src, got)
		}
		if strings.HasPrefix(src, "#") && !strings.HasPrefix(got, src) {
			t.Errorf("comment lost: %q", got)
		}
	}
}

// The shipped config template round-trips: an unedited parse renders the same
// bytes, a scalar edit changes exactly one line, and inserts and list edits
// keep every comment line and every ${VAR} placeholder.
func TestShippedTemplateRoundTrip(t *testing.T) {
	src := string(public.DefaultConfigYAML)
	d, err := Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if got := renderSpliced(t, d); got != src {
		t.Fatal("unedited template does not render byte-identical")
	}

	d, _ = Parse([]byte(src))
	if err := d.Set([]string{"notify", "enabled"}, mustNode(t, true)); err != nil {
		t.Fatal(err)
	}
	got := renderSpliced(t, d)
	if dl := diffLines(src, got); len(dl) != 1 {
		t.Fatalf("scalar edit changed lines %v", dl)
	}

	d, _ = Parse([]byte(src))
	steps := []func() error{
		func() error { return d.Set([]string{"notify", "telegram", "extra_key"}, mustNode(t, "v")) },
		func() error {
			_, err := d.AppendUnique([]string{"scope", "host", "exclude"}, mustNode(t, "x.example"))
			return err
		},
		func() error {
			return d.Set([]string{"dynamic-assessment", "enabled_modules", "active_modules"}, mustNode(t, []string{"a", "b"}))
		},
		func() error { return d.Set([]string{"oast", "server_url"}, mustNode(t, "oast.example")) },
	}
	for i, step := range steps {
		if err := step(); err != nil {
			t.Fatalf("step %d: %v", i, err)
		}
	}
	got = renderSpliced(t, d)
	for _, line := range strings.Split(src, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") && !strings.Contains(got, line) {
			t.Errorf("comment line lost: %q", line)
		}
		if strings.Contains(line, "${") && !strings.Contains(line, "server_url") && !strings.Contains(got, line) {
			t.Errorf("placeholder line lost: %q", line)
		}
	}
	if !strings.Contains(got, "server_url: oast.example") {
		t.Error("oast.server_url not set")
	}
	if n := strings.Count(got, "\n"); n < strings.Count(src, "\n") {
		t.Errorf("rendered %d lines from %d", n, strings.Count(src, "\n"))
	}
}

// A splice the self-check rejects falls back to a full re-encode that still
// holds the edit.
func TestMultilineScalarFallsBackSafely(t *testing.T) {
	src := "a: |\n  line1\n  line2\nb: 'it''s'\nc: \"x\\\"y\"\n"
	d, _ := Parse([]byte(src))
	if err := d.Set([]string{"a"}, mustNode(t, "one")); err != nil {
		t.Fatal(err)
	}
	if err := d.Set([]string{"b"}, mustNode(t, "z")); err != nil {
		t.Fatal(err)
	}
	if err := d.Set([]string{"c"}, mustNode(t, "w")); err != nil {
		t.Fatal(err)
	}
	got := render(t, d)
	var v map[string]string
	if err := yaml.Unmarshal([]byte(got), &v); err != nil {
		t.Fatal(err)
	}
	if v["a"] != "one" || v["b"] != "z" || v["c"] != "w" {
		t.Fatalf("got %q -> %v", got, v)
	}
	if got != "a: one\nb: 'z'\nc: \"w\"\n" {
		t.Errorf("got %q", got)
	}
}
