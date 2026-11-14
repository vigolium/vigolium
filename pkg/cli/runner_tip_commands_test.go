package cli

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// runnerTipRe captures the text after "vigolium " in a string literal, up to
// the first character that ends an inline command in prose.
var runnerTipRe = regexp.MustCompile("vigolium ([a-z][^'\"`;—)]*)")

var runnerTipWordRe = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)

// TestRunnerTipCommandsResolve parses every `vigolium <cmd> …` string the scan
// runner prints (tips, hints, error advice) and checks it names a runnable
// command that accepts the positional arguments shown. A tip like
// `vigolium config discovery.enrich_targets=true` lands on the `config` group
// and only prints help, which reads as the advice not working.
func TestRunnerTipCommandsResolve(t *testing.T) {
	dir := filepath.Join("..", "..", "internal", "runner")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	checked := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		path := filepath.Join(dir, name)
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			s, err := strconv.Unquote(lit.Value)
			if err != nil {
				return true
			}
			for _, m := range runnerTipRe.FindAllStringSubmatch(s, -1) {
				checked++
				if msg := checkTipCommand(m[1]); msg != "" {
					t.Errorf("%s: tip %q: %s", fset.Position(lit.Pos()), "vigolium "+strings.TrimSpace(m[1]), msg)
				}
			}
			return true
		})
	}
	if checked == 0 {
		t.Fatal("found no vigolium tip strings in internal/runner; the scan is broken")
	}
}

func checkTipCommand(text string) string {
	var words, positional []string
	for _, tok := range strings.Fields(text) {
		tok = strings.TrimRight(tok, ",.:")
		if tok == "" || strings.HasPrefix(tok, "-") || strings.ContainsAny(tok, "%<") {
			break
		}
		if len(positional) == 0 && runnerTipWordRe.MatchString(tok) {
			words = append(words, tok)
			continue
		}
		positional = append(positional, tok)
	}
	if len(words) == 0 {
		return ""
	}
	cmd, rest, err := rootCmd.Find(words)
	if err != nil || cmd == rootCmd {
		return "does not name a vigolium command"
	}
	if !cmd.Runnable() {
		return "resolves to the command group " + strconv.Quote(cmd.CommandPath()) + ", which only prints help"
	}
	args := append(append([]string{}, rest...), positional...)
	if len(args) > 0 && cmd.Args != nil {
		if err := cmd.Args(cmd, args); err != nil {
			return "arguments rejected by " + cmd.CommandPath() + ": " + err.Error()
		}
	}
	return ""
}
