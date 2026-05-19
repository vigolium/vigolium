package testutil

import (
	"net/url"
	"time"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
)

// Common HTML snippets for testing

// SimpleHTML is a minimal HTML document.
const SimpleHTML = `<!DOCTYPE html>
<html>
<head><title>Simple Page</title></head>
<body><h1>Hello World</h1></body>
</html>`

// ClickableHTML contains various clickable elements.
const ClickableHTML = `<!DOCTYPE html>
<html>
<head><title>Clickable Test</title></head>
<body>
	<a href="#" id="link1">Link 1</a>
	<a href="page2.html" id="link2">Link 2</a>
	<button id="btn1">Button 1</button>
	<button id="btn2" onclick="alert('clicked')">Button 2</button>
	<input type="submit" id="submit1" value="Submit">
	<input type="button" id="inputbtn" value="Input Button">
	<div id="clickdiv" onclick="handleClick()">Clickable Div</div>
	<span id="notclickable">Not Clickable</span>
</body>
</html>`

// FormHTML contains a form with various input types.
const FormHTML = `<!DOCTYPE html>
<html>
<head><title>Form Test</title></head>
<body>
	<form id="testform" action="/submit" method="post">
		<input type="text" name="username" id="user" placeholder="Username">
		<input type="password" name="password" id="pass" placeholder="Password">
		<input type="email" name="email" id="email" placeholder="Email">
		<input type="hidden" name="csrf" value="token123">
		<select name="country" id="country">
			<option value="">Select Country</option>
			<option value="us">USA</option>
			<option value="uk">UK</option>
			<option value="vn">Vietnam</option>
		</select>
		<textarea name="bio" id="bio" rows="3"></textarea>
		<input type="checkbox" name="agree" id="agree" value="yes">
		<input type="radio" name="gender" value="male" id="male">
		<input type="radio" name="gender" value="female" id="female">
		<input type="submit" value="Login">
	</form>
</body>
</html>`

// DynamicHTML contains elements that might change between page loads.
const DynamicHTML = `<!DOCTYPE html>
<html>
<head><title>Dynamic Content</title></head>
<body>
	<div id="static">Static Content</div>
	<div id="dynamic">Time: <span id="time">12:00:00</span></div>
	<div id="ads" class="advertisement">Advertisement Here</div>
	<div id="session">Session: abc123</div>
	<div id="content">Main content stays the same</div>
</body>
</html>`

// IFrameHTML contains nested iframes.
const IFrameHTML = `<!DOCTYPE html>
<html>
<head><title>IFrame Test</title></head>
<body>
	<h1>Main Page</h1>
	<iframe id="frame1" src="frame1.html"></iframe>
	<iframe id="frame2" src="frame2.html"></iframe>
</body>
</html>`

// ScriptHTML contains script tags that should be stripped.
const ScriptHTML = `<!DOCTYPE html>
<html>
<head>
	<title>Script Test</title>
	<script>document.write("Hello");</script>
	<script src="external.js"></script>
</head>
<body>
	<div id="content">Content</div>
	<script>
		function test() { return 1; }
	</script>
</body>
</html>`

// StyleHTML contains style elements that should be stripped.
const StyleHTML = `<!DOCTYPE html>
<html>
<head>
	<title>Style Test</title>
	<style>body { color: red; }</style>
	<link rel="stylesheet" href="style.css">
</head>
<body>
	<div id="content" style="color: blue;">Content</div>
</body>
</html>`

// AttributeHTML contains various attributes for testing stripping.
const AttributeHTML = `<!DOCTYPE html>
<html>
<head><title>Attribute Test</title></head>
<body>
	<div id="div1" class="container" style="color:red" data-test="value" data-id="123">
		<span id="span1" class="highlight" onclick="click()">Text</span>
	</div>
</body>
</html>`

// NewTestConfig creates a minimal config for testing.
func NewTestConfig(targetURL string) *config.Config {
	u, _ := url.Parse(targetURL)
	if u.Scheme == "" {
		u.Scheme = "http"
	}
	return &config.Config{
		URL:             u,
		MaxDepth:        2,
		MaxStates:       10,
		MaxDuration:     0,
		Headless:        true,
		BrowserCount:    1,
		WaitAfterReload: 200 * time.Millisecond,
		WaitAfterEvent:  200 * time.Millisecond,
		PageLoadTimeout: 30 * time.Second,
		DOMStableTime:   500 * time.Millisecond,
		ClickSelectors:  config.DefaultClickSelectors(),
		DOMStripTags:    config.DefaultStripTags(),
		DOMStripAttrs:   config.DefaultStripAttrs(),
		FormFillEnabled: true,
		FormFillMode:    config.FormFillNormal,
		CrawlFrames:     true,
	}
}

// SimpleSiteExpected contains expected values for simple-site tests.
var SimpleSiteExpected = struct {
	NumberOfStates int
	NumberOfEdges  int
}{
	NumberOfStates: 4, // index, a, b, c
	NumberOfEdges:  7, // index->a, index->b, b->c, c->b, c->index (+ duplicates may vary)
}

// DOMTestExpected contains expected values for domtest.html tests.
var DOMTestExpected = struct {
	Title         string
	HasScripts    bool
	HasStyles     bool
	NumClickables int
	TopMenuItems  int
	LeftMenuItems int
}{
	Title:         "An Ajax Test Site",
	HasScripts:    true,
	HasStyles:     true,
	NumClickables: 15, // Approximate count of clickable elements
	TopMenuItems:  5,  // Home, Organizers, PC, CFP, Contact
	LeftMenuItems: 6,  // Topics, Dates, Submission, testdiv, testspan1, etc.
}
