// Package main ...
package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"

	"github.com/vigolium/vigolium/pkg/spitolas/rod"
	"github.com/vigolium/vigolium/pkg/spitolas/rod/lib/proto"
)

func main() {
	// create a test server to serve the page
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Title</title>
</head>
<body>
<h1 id="title" class="link">
    <a href="https://test.com/helloworld">
        content of h1 1
    </a>
    <span>hello</span> world
</h1>
</body>
</html>
`,
		)
	}))
	defer ts.Close()

	page := rod.New().MustConnect().MustPage(ts.URL)

	node, err := page.MustElement("body").Describe(-1, true)
	if err != nil {
		log.Fatal(err)
	}

	printNodes(os.Stdout, node.Children, "", "  ")
}

func printNodes(w io.Writer, nodes []*proto.DOMNode, padding, indent string) {
	for _, node := range nodes {
		switch node.NodeName {
		case "#text":
			_, _ = fmt.Fprintf(w, "%s#text: %q\n", padding, node.NodeValue)
		default:
			_, _ = fmt.Fprintf(w, "%s%s:\n", padding, strings.ToLower(node.NodeName))
			if n := len(node.Attributes); n > 0 {
				_, _ = fmt.Fprintf(w, "%sattributes:\n", padding+indent)
				for i := 0; i < n; i += 2 {
					_, _ = fmt.Fprintf(w, "%s%s: %q\n", padding+indent+indent, node.Attributes[i], node.Attributes[i+1])
				}
			}
		}
		if node.ChildNodeCount != nil {
			_, _ = fmt.Fprintf(w, "%schildren:\n", padding+indent)
			printNodes(w, node.Children, padding+indent+indent, indent)
		}
	}
}
