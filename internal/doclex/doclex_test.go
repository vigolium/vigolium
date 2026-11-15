package doclex

import (
	"fmt"
	"testing"
)

// Pin the lexer cases that bit the prototype.
func TestShellLexer(t *testing.T) {
	cases := []struct {
		line string
		want [][]string
	}{
		{`vigolium finding --id <id> -j`, [][]string{{"finding", "--id", "PLACEHOLDER", "-j"}}},
		{`vigolium scan -t https://x 2>&1 | tee out.log`, [][]string{{"scan", "-t", "https://x"}}},
		{`eval "$(vigolium project use <uuid> --shell)"`, [][]string{{"project", "use", "PLACEHOLDER", "--shell"}}},
		{`VIGOLIUM_DB_PATH=/tmp/x.db timeout 60 vigolium db stats -j > s.json`, [][]string{{"db", "stats", "-j"}}},
		{`cat ids.txt | xargs -I{} vigolium finding --id {}`, [][]string{{"finding", "--id", "{}"}}},
		{`vigolium ext eval 'vigolium.log.info("a # b")' # comment`, [][]string{{"ext", "eval", `vigolium.log.info("a # b")`}}},
		{`./bin/vigolium version && echo ok`, [][]string{{"version"}}},
		{`$(go env GOPATH)/bin/vigolium version`, [][]string{{"version"}}},
		{"watch -n 5 'vigolium scan status <uuid>'", [][]string{{"scan", "status", "PLACEHOLDER"}}},
		{"vigolium ingest -I openapi < spec.yaml", [][]string{{"ingest", "-I", "openapi"}}},
		{"vigolium scan -t \"$TARGET\" --format jsonl", [][]string{{"scan", "-t", "PLACEHOLDER", "--format", "jsonl"}}},
		{"vigolium storage rm a b ...", [][]string{{"storage", "rm", "a", "b", Ellipsis}}},
		{`vigolium olium --prompt "..."`, [][]string{{"olium", "--prompt", "PLACEHOLDER"}}},
		{"vigolium ffuf -j -- <ffuf flags>", [][]string{{"ffuf", "-j", "--", "PLACEHOLDER"}}},
	}
	for _, tc := range cases {
		got := ShellCommands(tc.line, 0)
		if fmt.Sprint(got) != fmt.Sprint(tc.want) {
			t.Errorf("%s\n  got  %q\n  want %q", tc.line, got, tc.want)
		}
	}

	lines := LogicalLines([]string{
		"$ vigolium scan \\",
		"    -t https://x",
		"vigolium ext eval --stdin <<'EOF'",
		"vigolium.nope()",
		"EOF",
		"→ output line",
		"vigolium version # doccheck: skip",
	}, 1, LinesShell, false)
	if len(lines) != 2 || lines[0].Text != "vigolium scan  -t https://x" || lines[1].Line != 3 {
		t.Errorf("logical lines: %+v", lines)
	}
}
