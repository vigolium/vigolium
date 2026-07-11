package modkit

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

func TestDetectDirectoryListingServer(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		body string
		want string
	}{
		{
			name: "apache index of title+h1",
			body: `<html><head><title>Index of /uploads</title></head>` +
				`<body><h1>Index of /uploads</h1><pre><a href="a.txt">a.txt</a></pre></body></html>`,
			want: "Apache",
		},
		{
			name: "nginx index of title+pre",
			body: `<html><head><title>Index of /files/</title></head><body>` +
				`<pre><a href="../">../</a><a href="dump.sql">dump.sql</a></pre></body></html>`,
			want: "Nginx",
		},
		{
			name: "jetty title+css",
			body: `<html><head><title>Directory: /webapp/</title>` +
				`<link href="jetty-dir.css" rel="stylesheet"></head><body></body></html>`,
			want: "Jetty",
		},
		{
			name: "iis structural signature",
			body: `<html><head><title>site - /uploads</title></head>` +
				`<body><H1>site - /uploads</H1><hr><pre><A HREF="a.txt">a.txt</A></pre></body></html>`,
			want: "IIS",
		},
		{
			name: "generic serve-index with file container",
			body: `<html><head><title>listing directory /public</title></head><body>` +
				`<h1>listing directory /public</h1><ul id="files"><li><a href="app.js">app.js</a></li></ul></body></html>`,
			want: "Generic",
		},
		{
			name: "generic python http.server with hr-bracketed list",
			body: `<html><head><title>Directory listing for /files/</title></head><body>` +
				`<h1>Directory listing for /files/</h1><hr><ul><li><a href="dump.sql">dump.sql</a></li></ul><hr></body></html>`,
			want: "Generic",
		},
		{
			name: "content page titled Directory of X, no structure",
			body: `<html><head><title>Directory of Physicians</title></head><body>` +
				`<h1>Find a Doctor</h1><ul><li><a href="/doctor/jane">Jane</a></li></ul></body></html>`,
			want: "",
		},
		{
			name: "content page titled Index of Terms, no structure",
			body: `<html><head><title>Index of Terms</title></head><body>` +
				`<h1>Glossary</h1><table><tr><td><a href="/term/abc">ABC</a></td></tr></table></body></html>`,
			want: "",
		},
		{
			name: "gatsby app page with listing-shaped title",
			body: `<html><head><meta name="generator" content="Gatsby 5.13.3">` +
				`<meta property="og:title" content="Index of /media"><title>Index of /media</title></head>` +
				`<body><h1>Index of /media</h1><hr><ul><li><a href="/m/1">One</a></li></ul></body></html>`,
			want: "",
		},
		{
			name: "ordinary page",
			body: `<html><head><title>Welcome</title></head><body>Hello</body></html>`,
			want: "",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, DetectDirectoryListingServer(tc.body))
		})
	}
}

// LooksLikeAppPage and HasParentDirLink take an already-lowercased body (the
// caller lowercases once and threads it through the classifiers), so the inputs
// here are lowercase.
func TestLooksLikeAppPage(t *testing.T) {
	t.Parallel()
	assert.True(t, LooksLikeAppPage(`<meta name="generator" content="gatsby 5.13.3">`))
	assert.True(t, LooksLikeAppPage(`<meta property="og:title" content="x">`))
	assert.True(t, LooksLikeAppPage(`<div data-react-helmet="true">`))
	assert.False(t, LooksLikeAppPage(`<html><head><title>index of /</title></head><body><pre></pre></body></html>`))
}

func TestHasParentDirLink(t *testing.T) {
	t.Parallel()
	assert.True(t, HasParentDirLink(`<a href="../">../</a>`))
	assert.True(t, HasParentDirLink(`<a href="/x/">parent directory</a>`))
	assert.False(t, HasParentDirLink(`<a href="/about">about</a>`))
}

func TestServiceBaseURL(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "https://example.com", ServiceBaseURL(httpmsg.NewServiceSecure("example.com", 443, true)))
	assert.Equal(t, "http://example.com", ServiceBaseURL(httpmsg.NewServiceSecure("example.com", 80, false)))
	assert.Equal(t, "https://example.com:8443", ServiceBaseURL(httpmsg.NewServiceSecure("example.com", 8443, true)))
	assert.Equal(t, "http://example.com:8080", ServiceBaseURL(httpmsg.NewServiceSecure("example.com", 8080, false)))
}
