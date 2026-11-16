package lab

import (
	"fmt"
	"html"
	"net/http"
	"path"
	"regexp"
	"strconv"
	"strings"
)

// Plant is one deliberately vulnerable route and its benign twin: the same
// shape and parameter, answered safely. A scanner that flags the twin has a
// false positive; one that misses the plant has a coverage gap.
type Plant struct {
	Class string // vulnerability class, e.g. "sqli-error"
	Path  string // vulnerable route
	Twin  string // benign twin route
	Param string // the injectable query parameter
	Seed  string // a harmless value for Param
}

// Plants lists every planted vulnerability in VulnApp.
func Plants() []Plant {
	return []Plant{
		{Class: "open-redirect", Path: "/redirect", Twin: "/redirect-safe", Param: "next", Seed: "account"},
		{Class: "xss-reflected", Path: "/search", Twin: "/search-safe", Param: "q", Seed: "shoes"},
		{Class: "sqli-error", Path: "/item", Twin: "/item-safe", Param: "id", Seed: "1"},
		{Class: "path-traversal", Path: "/file", Twin: "/file-safe", Param: "name", Seed: "readme.txt"},
		{Class: "ssti", Path: "/greet", Twin: "/greet-safe", Param: "name", Seed: "guest"},
		{Class: "command-injection", Path: "/ping", Twin: "/ping-safe", Param: "host", Seed: "example"},
	}
}

// URL returns the plant's vulnerable URL under base.
func (p Plant) URL(base string) string { return base + p.Path + "?" + p.Param + "=" + p.Seed }

// TwinURL returns the benign twin's URL under base.
func (p Plant) TwinURL(base string) string { return base + p.Twin + "?" + p.Param + "=" + p.Seed }

// PlantURLs lists every plant's vulnerable URL, benign twin URL, or both
// (interleaved, plant first) under base.
func PlantURLs(base string, vulnerable, twins bool) []string {
	var out []string
	for _, p := range Plants() {
		if vulnerable {
			out = append(out, p.URL(base))
		}
		if twins {
			out = append(out, p.TwinURL(base))
		}
	}
	return out
}

// VulnAppOptions shape VulnApp.
type VulnAppOptions struct {
	// OffsiteLinks are absolute URLs the index page links to and the forms
	// post to — an out-of-scope sentinel goes here, so a crawler that follows
	// them shows up in the sentinel's ledger.
	OffsiteLinks []string
	// ExtraLinks are more in-scope paths the index links to (Minefield's
	// hostile endpoints).
	ExtraLinks []string
}

// VulnApp is a small site whose index links to every plant and twin.
func VulnApp(opts VulnAppOptions) http.Handler {
	// The index and the script never change for a given opts: build once.
	var index, script strings.Builder
	index.WriteString("<html><head><title>lab shop</title></head><body><h1>lab shop</h1><ul>\n")
	script.WriteString("const api = {\n")
	for _, p := range Plants() {
		fmt.Fprintf(&index, "<li><a href=\"%s\">%s</a> <a href=\"%s\">%s (safe)</a></li>\n",
			html.EscapeString(p.URL("")), p.Class, html.EscapeString(p.TwinURL("")), p.Class)
		fmt.Fprintf(&script, "  %q: %q,\n", p.Class, p.URL(""))
	}
	for _, l := range opts.ExtraLinks {
		fmt.Fprintf(&index, "<li><a href=\"%s\">%s</a></li>\n", html.EscapeString(l), html.EscapeString(l))
	}
	for _, l := range opts.OffsiteLinks {
		fmt.Fprintf(&index, "<li><a href=\"%s\">partner</a></li>\n", html.EscapeString(l))
		fmt.Fprintf(&script, "  partner: %q,\n", l)
	}
	index.WriteString("</ul><form action=\"/search\" method=\"get\"><input name=\"q\"><button>go</button></form>\n")
	for _, l := range opts.OffsiteLinks {
		fmt.Fprintf(&index, "<form action=\"%s\" method=\"post\"><input name=\"email\"></form>\n", html.EscapeString(l))
	}
	index.WriteString("<script src=\"/static/app.js\"></script></body></html>\n")
	script.WriteString("};\n")
	indexBody, scriptBody := index.String(), []byte(script.String())

	mux := http.NewServeMux()
	mux.HandleFunc("/{$}", func(w http.ResponseWriter, _ *http.Request) {
		writeHTML(w, http.StatusOK, indexBody)
	})
	mux.HandleFunc("/static/app.js", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = w.Write(scriptBody)
	})

	// open redirect: Location is whatever `next` says.
	mux.HandleFunc("/redirect", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", r.URL.Query().Get("next"))
		w.WriteHeader(http.StatusFound)
	})
	mux.HandleFunc("/redirect-safe", func(w http.ResponseWriter, r *http.Request) {
		next := r.URL.Query().Get("next")
		if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") || strings.ContainsAny(next, "\\\r\n") {
			next = "/"
		}
		w.Header().Set("Location", next)
		w.WriteHeader(http.StatusFound)
	})

	// reflected XSS: q echoed into HTML unescaped.
	mux.HandleFunc("/search", func(w http.ResponseWriter, r *http.Request) {
		writeHTML(w, http.StatusOK, "<html><body><h2>Results for "+r.URL.Query().Get("q")+"</h2><p>No items.</p></body></html>")
	})
	mux.HandleFunc("/search-safe", func(w http.ResponseWriter, r *http.Request) {
		writeHTML(w, http.StatusOK, "<html><body><h2>Results for "+html.EscapeString(r.URL.Query().Get("q"))+"</h2><p>No items.</p></body></html>")
	})

	// error-based SQLi: the id is concatenated into a quoted literal and an
	// unbalanced quote surfaces the database's own error.
	mux.HandleFunc("/item", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		if strings.Count(id, "'")%2 == 1 || strings.Count(id, `"`)%2 == 1 || strings.Contains(id, `\`) {
			writeHTML(w, http.StatusInternalServerError, fmt.Sprintf(
				"<html><body><b>Fatal error</b>: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '%s' LIMIT 1' at line 1</body></html>",
				html.EscapeString(id)))
			return
		}
		writeItem(w, id)
	})
	mux.HandleFunc("/item-safe", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		if _, err := strconv.Atoi(id); err != nil {
			writeHTML(w, http.StatusBadRequest, "<html><body>invalid item id</body></html>")
			return
		}
		writeItem(w, id)
	})

	// path traversal: name is joined onto the files root without containment.
	mux.HandleFunc("/file", func(w http.ResponseWriter, r *http.Request) {
		name := strings.ReplaceAll(r.URL.Query().Get("name"), `\`, "/")
		p := name
		if !strings.HasPrefix(name, "/") {
			p = path.Join("/var/www/files", name)
		}
		serveFakeFile(w, path.Clean(p))
	})
	mux.HandleFunc("/file-safe", func(w http.ResponseWriter, r *http.Request) {
		name := path.Base(strings.ReplaceAll(r.URL.Query().Get("name"), `\`, "/"))
		serveFakeFile(w, path.Join("/var/www/files", name))
	})

	// SSTI: arithmetic inside template delimiters is evaluated.
	mux.HandleFunc("/greet", func(w http.ResponseWriter, r *http.Request) {
		writeHTML(w, http.StatusOK, "<html><body>Hello "+renderTemplate(r.URL.Query().Get("name"))+"!</body></html>")
	})
	mux.HandleFunc("/greet-safe", func(w http.ResponseWriter, r *http.Request) {
		writeHTML(w, http.StatusOK, "<html><body>Hello "+html.EscapeString(r.URL.Query().Get("name"))+"!</body></html>")
	})

	// command injection: `ping -c 1 <host>` through a shell.
	mux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		writeHTML(w, http.StatusOK, "<html><body><pre>"+html.EscapeString(fakeShell("ping -c 1 "+r.URL.Query().Get("host")))+"</pre></body></html>")
	})
	mux.HandleFunc("/ping-safe", func(w http.ResponseWriter, r *http.Request) {
		host := r.URL.Query().Get("host")
		if !hostname.MatchString(host) {
			writeHTML(w, http.StatusBadRequest, "<html><body>invalid host</body></html>")
			return
		}
		writeHTML(w, http.StatusOK, "<html><body><pre>"+html.EscapeString(pingOutput(host))+"</pre></body></html>")
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		writeHTML(w, http.StatusNotFound, "<html><body>not found</body></html>")
	})
	return mux
}

func writeHTML(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

func writeItem(w http.ResponseWriter, id string) {
	writeHTML(w, http.StatusOK, "<html><body><h2>Item "+html.EscapeString(id)+"</h2><p>A fine item.</p></body></html>")
}

var fakeFiles = map[string]string{
	"/var/www/files/readme.txt": "Welcome to the lab shop file share.\n",
	"/etc/passwd": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n" +
		"bin:x:2:2:bin:/bin:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n",
	"/etc/hosts":          "127.0.0.1\tlocalhost\n::1\tlocalhost ip6-localhost ip6-loopback\n",
	"/windows/win.ini":    "; for 16-bit app support\n[fonts]\n[extensions]\n[mci extensions]\n[files]\n[Mail]\nMAPI=1\n",
	"/c:/windows/win.ini": "; for 16-bit app support\n[fonts]\n[extensions]\n[mci extensions]\n[files]\n[Mail]\nMAPI=1\n",
	"/proc/self/environ":  "PATH=/usr/local/bin:/usr/bin:/bin\x00HOME=/var/www\x00",
}

func serveFakeFile(w http.ResponseWriter, p string) {
	body, ok := fakeFiles[strings.ToLower(p)]
	if !ok {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("file not found\n"))
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write([]byte(body))
}

var (
	hostname     = regexp.MustCompile(`^[A-Za-z0-9.-]{1,253}$`)
	templateExpr = regexp.MustCompile(`(?:\{\{|\$\{|#\{|<%=|\{)\s*(-?\d+)\s*([*+])\s*(-?\d+)\s*(?:\}\}|\}|%>)`)
)

// arith evaluates `a op b` for op `+` or `*`, the only arithmetic the lab's
// fake template engine and shell understand.
func arith(a, op, b string) string {
	x, _ := strconv.Atoi(a)
	y, _ := strconv.Atoi(b)
	if op == "+" {
		return strconv.Itoa(x + y)
	}
	return strconv.Itoa(x * y)
}

// replaceArith rewrites every match of re (groups: a, op, b) with its value.
func replaceArith(re *regexp.Regexp, s string) string {
	return re.ReplaceAllStringFunc(s, func(m string) string {
		g := re.FindStringSubmatch(m)
		return arith(g[1], g[2], g[3])
	})
}

// renderTemplate evaluates `a*b` / `a+b` inside the common template
// delimiters, the way an engine rendering user input would.
func renderTemplate(s string) string { return replaceArith(templateExpr, s) }

var (
	shellSplit = regexp.MustCompile("\\s*(?:;|&&|&|\\|\\||\\||\n|`|\\$\\()\\s*")
	echoArg    = regexp.MustCompile(`^echo\s+(?:-n\s+|-e\s+)?['"]?(.*?)['"]?\)?$`)
	exprArith  = regexp.MustCompile(`^expr\s+(-?\d+)\s*\\?([*+])\s*(-?\d+)`)
	shellArith = regexp.MustCompile(`\$\(\((-?\d+)\s*([*+])\s*(-?\d+)\)\)`)
)

// fakeShell runs cmdline through a pretend shell: the first command is the
// ping, each separator-chained command after it is "executed".
func fakeShell(cmdline string) string {
	// Arithmetic expansion happens before the line is split, as in a shell,
	// so `$((a+b))` is not mistaken for a `$(` command substitution.
	parts := shellSplit.Split(replaceArith(shellArith, cmdline), -1)
	var out strings.Builder
	for i, part := range parts {
		part = strings.TrimSpace(strings.TrimRight(part, ")`"))
		echo, expr := echoArg.FindStringSubmatch(part), exprArith.FindStringSubmatch(part)
		switch {
		case i == 0:
			out.WriteString(pingOutput(strings.TrimPrefix(part, "ping -c 1 ")))
		case part == "id" || strings.HasPrefix(part, "id "):
			out.WriteString("uid=33(www-data) gid=33(www-data) groups=33(www-data)\n")
		case part == "whoami":
			out.WriteString("www-data\n")
		case strings.HasPrefix(part, "cat /etc/passwd"):
			out.WriteString(fakeFiles["/etc/passwd"])
		case echo != nil:
			out.WriteString(echo[1] + "\n")
		case expr != nil:
			out.WriteString(arith(expr[1], expr[2], expr[3]) + "\n")
		case part == "":
		default:
			fmt.Fprintf(&out, "sh: 1: %s: not found\n", strings.Fields(part)[0])
		}
	}
	return out.String()
}

func pingOutput(host string) string {
	if host == "" {
		return "ping: usage error: Destination address required\n"
	}
	return fmt.Sprintf("PING %s (93.184.215.14) 56(84) bytes of data.\n64 bytes from 93.184.215.14: icmp_seq=1 ttl=56 time=11.2 ms\n", host)
}
