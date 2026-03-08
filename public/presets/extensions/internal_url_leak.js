// internal_url_leak.js
// Passive module: Detects internal/private URLs and IP addresses leaked in
// HTTP response bodies, including .internal, .local, .corp, .dev, .staging
// domains, RFC1918 IPs, and localhost references.

var SKIP_CONTENT_TYPES = ["css", "javascript", "image/", "font/"];

var PATTERNS = [
  { id: "internal-domain", regex: "https?://[\\w.-]+\\.internal(?:[:/\\s\"']|$)" },
  { id: "local-domain", regex: "https?://[\\w.-]+\\.local(?:[:/\\s\"']|$)" },
  { id: "corp-domain", regex: "https?://[\\w.-]+\\.corp(?:[:/\\s\"']|$)" },
  { id: "dev-domain", regex: "https?://[\\w.-]+\\.dev\\.\\w+(?:[:/\\s\"']|$)" },
  { id: "staging-domain", regex: "https?://[\\w.-]+\\.staging(?:[:/\\s\"']|$)" },
  { id: "rfc1918-10", regex: "https?://10\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}[:/]" },
  { id: "rfc1918-172", regex: "https?://172\\.(?:1[6-9]|2\\d|3[01])\\.\\d{1,3}\\.\\d{1,3}[:/]" },
  { id: "rfc1918-192", regex: "https?://192\\.168\\.\\d{1,3}\\.\\d{1,3}[:/]" },
  { id: "localhost", regex: "https?://localhost:\\d+" }
];

// Extract regex to capture full URL
var URL_EXTRACT_PATTERNS = [
  { id: "internal-url", regex: "(https?://[\\w.-]+\\.(?:internal|local|corp|staging)(?:[:/][^\\s\"'<>]*)?)" },
  { id: "rfc1918-url", regex: "(https?://(?:10\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}|172\\.(?:1[6-9]|2\\d|3[01])\\.\\d{1,3}\\.\\d{1,3}|192\\.168\\.\\d{1,3}\\.\\d{1,3})(?:[:/][^\\s\"'<>]*)?)" },
  { id: "localhost-url", regex: "(https?://localhost:\\d+[^\\s\"'<>]*)" }
];

function shouldSkip(contentType) {
  if (!contentType) return false;
  var ct = contentType.toLowerCase();
  for (var i = 0; i < SKIP_CONTENT_TYPES.length; i++) {
    if (ct.indexOf(SKIP_CONTENT_TYPES[i]) !== -1) return true;
  }
  return false;
}

module.exports = {
  id: "internal-url-leak",
  name: "Internal URL Leak in Response",
  description: "Detects internal/private URLs and IP addresses leaked in HTTP response bodies",
  type: "passive",
  severity: "low",
  confidence: "tentative",
  scope: "response",
  tags: ["exposure", "information-disclosure", "light"],
  scanTypes: ["per_request"],

  scanPerRequest: function(ctx) {
    if (!ctx.response || !ctx.response.body) return null;

    var contentType = ctx.response.headers ? ctx.response.headers["content-type"] || "" : "";
    if (shouldSkip(contentType)) return null;

    var body = ctx.response.body;
    var matched = [];
    var remarkTags = [];

    // Check each pattern for presence
    for (var i = 0; i < PATTERNS.length; i++) {
      var pattern = PATTERNS[i];
      if (vigolium.utils.regexMatch(body, pattern.regex)) {
        remarkTags.push("internal-url:" + pattern.id);
      }
    }

    if (remarkTags.length === 0) return null;

    // Extract actual URLs for reporting
    for (var j = 0; j < URL_EXTRACT_PATTERNS.length; j++) {
      var ep = URL_EXTRACT_PATTERNS[j];
      var extracted = vigolium.utils.regexExtract(body, ep.regex);
      if (extracted) {
        for (var k = 0; k < extracted.length && k < 10; k++) {
          if (matched.indexOf(extracted[k]) === -1) {
            matched.push(extracted[k]);
          }
        }
      }
    }

    if (ctx.record && ctx.record.uuid) {
      ctx.record.addRemarks(remarkTags);
    }

    var description = "Response body contains internal/private URLs:\n" +
      matched.map(function(u) { return "- `" + u + "`"; }).join("\n") +
      "\n\nThese may reveal internal infrastructure details.";

    return [{
      url: ctx.request ? ctx.request.url : "",
      matched: matched.join(", "),
      name: "Internal URL Leak in Response",
      description: description,
      severity: "low"
    }];
  }
};
