package sqli_time_blind

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// MySQL treats "--" as a comment only when whitespace follows; a template
// ending in a bare "--" is a syntax error on MySQL. Every MySQL
// comment-terminated template must end "-- -", and the default (non-risky)
// tier must cover each backend in both contexts it can reach without a comment.
func TestTemplateGrammar(t *testing.T) {
	for _, set := range [][]timePair{stringPayloads, numericPayloads} {
		for _, p := range set {
			if p.dbType == "mysql" && strings.HasSuffix(p.template, "--") {
				t.Errorf("MySQL template %q ends in a bare -- (not a MySQL comment)", p.template)
			}
			if strings.Count(p.template, "%d") != 1 {
				t.Errorf("template %q must carry exactly one %%d", p.template)
			}
			if p.dbType == "sqlite" {
				t.Errorf("SQLite has no scalable delay; template %q must not exist", p.template)
			}
		}
	}
	type key struct{ ctx, db string }
	normal := map[key]bool{}
	for _, v := range []string{"hello", "42"} {
		for _, p := range getPayloadsForValue(v, false) {
			normal[key{p.context, p.dbType}] = true
		}
	}
	for _, k := range []key{{"string", "mysql"}, {"string", "postgres"}, {"string", "oracle"},
		{"numeric", "mysql"}, {"numeric", "postgres"}} {
		if !normal[k] {
			t.Errorf("default tier lacks a %s %s payload", k.ctx, k.db)
		}
	}
}

// mysqlGrammarRe accepts only what MySQL would parse after "id=1": an AND
// SLEEP(n) that either ends the statement or is followed by a real comment
// ("-- " with whitespace).
var mysqlGrammarRe = regexp.MustCompile(`^1 AND SLEEP\((\d+)\)(-- .*)?$`)

// A MySQL sink sleeps only on grammatical input. With the old " AND SLEEP(n)--"
// template the server never slept (bare "--" is not a comment), so the module
// could not find the injection.
func TestScanPerRequest_MySQLCommentGrammar(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping multi-second timing test in -short mode")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if m := mysqlGrammarRe.FindStringSubmatch(r.URL.Query().Get("id")); m != nil {
			n, _ := strconv.Atoi(m[1])
			flushAndSleep(w, time.Duration(n)*time.Second)
			return
		}
		flushAndSleep(w, baseDelay)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/item?id=1")
	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "a MySQL sink that sleeps only on valid comment grammar must be found")
}
