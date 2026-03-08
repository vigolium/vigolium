// csp_directive_evaluator.js
// Passive module: Evaluates Content-Security-Policy headers for weak directives
// such as unsafe-inline, unsafe-eval, data: URIs in script-src, bare wildcards,
// missing frame-ancestors, and permissive default-src.

var WEAK_CHECKS = [
  { id: "unsafe-inline", directives: ["script-src", "default-src"], value: "'unsafe-inline'" },
  { id: "unsafe-eval", directives: ["script-src", "default-src"], value: "'unsafe-eval'" },
  { id: "data-uri-script", directives: ["script-src"], value: "data:" },
  { id: "wildcard", directives: ["default-src", "script-src", "object-src", "frame-src"], value: "*" }
];

function parseCSP(header) {
  var directives = {};
  var parts = header.split(";");
  for (var i = 0; i < parts.length; i++) {
    var trimmed = parts[i].trim();
    if (!trimmed) continue;
    var tokens = trimmed.split(/\s+/);
    var name = tokens[0].toLowerCase();
    directives[name] = tokens.slice(1);
  }
  return directives;
}

module.exports = {
  id: "csp-directive-evaluator",
  name: "CSP Directive Evaluator",
  description: "Evaluates Content-Security-Policy headers for weak or misconfigured directives",
  type: "passive",
  severity: "medium",
  confidence: "firm",
  scope: "response",
  tags: ["csp", "headers", "misconfiguration", "light"],
  scanTypes: ["per_request"],

  scanPerRequest: function(ctx) {
    if (!ctx.response || !ctx.response.headers) return null;

    var cspHeader = ctx.response.headers["content-security-policy"];
    if (!cspHeader) return null;

    var directives = parseCSP(cspHeader);
    var issues = [];
    var remarkTags = [];

    // Check for weak values in directives
    for (var i = 0; i < WEAK_CHECKS.length; i++) {
      var check = WEAK_CHECKS[i];
      for (var j = 0; j < check.directives.length; j++) {
        var dirName = check.directives[j];
        var values = directives[dirName];
        if (values) {
          for (var k = 0; k < values.length; k++) {
            if (values[k].toLowerCase() === check.value) {
              issues.push("- **" + check.id + "** in `" + dirName + "`");
              remarkTags.push("csp-weak:" + check.id);
              break;
            }
          }
        }
      }
    }

    // Check missing frame-ancestors
    if (!directives["frame-ancestors"]) {
      issues.push("- **missing frame-ancestors** (clickjacking risk)");
      remarkTags.push("csp-weak:missing-frame-ancestors");
    }

    // Check permissive default-src
    var defaultSrc = directives["default-src"];
    if (defaultSrc) {
      for (var d = 0; d < defaultSrc.length; d++) {
        if (defaultSrc[d] === "*" || defaultSrc[d] === "'unsafe-inline'" || defaultSrc[d] === "'unsafe-eval'") {
          // Already caught above, skip duplicates
          break;
        }
      }
    } else {
      issues.push("- **missing default-src** (no fallback policy)");
      remarkTags.push("csp-weak:missing-default-src");
    }

    if (issues.length === 0) return null;

    if (ctx.record && ctx.record.uuid) {
      ctx.record.addRemarks(remarkTags);
    }

    var description = "Content-Security-Policy contains weak directives:\n" +
      issues.join("\n") +
      "\n\nCSP: `" + cspHeader.substring(0, 200) + (cspHeader.length > 200 ? "...`" : "`");

    return [{
      url: ctx.request ? ctx.request.url : "",
      matched: remarkTags.join(", "),
      name: "Weak Content-Security-Policy",
      description: description,
      severity: "medium"
    }];
  }
};
