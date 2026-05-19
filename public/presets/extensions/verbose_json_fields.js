// verbose_json_fields.js
// Passive module: Detects verbose or sensitive field names in JSON response
// bodies that may indicate over-exposure of internal data (password hashes,
// secret keys, admin flags, debug info, database credentials).

var SENSITIVE_FIELDS_REGEX = "\"(?:password_hash|password_digest|secret_key|is_admin|__v|_id|internal_ip|debug|stack_trace|database_url|db_password|private_key)\"\\s*:";

var SKIP_CONTENT_TYPES = ["javascript", "css", "image/", "font/"];

function shouldSkip(contentType) {
  if (!contentType) return false;
  var ct = contentType.toLowerCase();
  for (var i = 0; i < SKIP_CONTENT_TYPES.length; i++) {
    if (ct.indexOf(SKIP_CONTENT_TYPES[i]) !== -1) return true;
  }
  return false;
}

// Individual field patterns for per-field reporting
var FIELD_PATTERNS = [
  { id: "password_hash", regex: "\"password_hash\"\\s*:" },
  { id: "password_digest", regex: "\"password_digest\"\\s*:" },
  { id: "secret_key", regex: "\"secret_key\"\\s*:" },
  { id: "is_admin", regex: "\"is_admin\"\\s*:" },
  { id: "__v", regex: "\"__v\"\\s*:" },
  { id: "_id", regex: "\"_id\"\\s*:" },
  { id: "internal_ip", regex: "\"internal_ip\"\\s*:" },
  { id: "debug", regex: "\"debug\"\\s*:" },
  { id: "stack_trace", regex: "\"stack_trace\"\\s*:" },
  { id: "database_url", regex: "\"database_url\"\\s*:" },
  { id: "db_password", regex: "\"db_password\"\\s*:" },
  { id: "private_key", regex: "\"private_key\"\\s*:" }
];

module.exports = {
  id: "verbose-json-fields",
  name: "Verbose JSON Field Detector",
  description: "Detects sensitive or verbose field names in JSON responses that may indicate over-exposure of internal data",
  type: "passive",
  severity: "medium",
  confidence: "tentative",
  scope: "response",
  tags: ["exposure", "sensitive-data", "api", "light"],
  scanTypes: ["per_request"],

  scanPerRequest: function(ctx) {
    if (!ctx.response || !ctx.response.body) return null;

    var contentType = ctx.response.headers ? ctx.response.headers["content-type"] || "" : "";
    if (contentType.toLowerCase().indexOf("json") === -1) return null;
    if (shouldSkip(contentType)) return null;

    var body = ctx.response.body;

    // Quick check with combined regex first
    if (!vigolium.utils.regexMatch(body, SENSITIVE_FIELDS_REGEX)) return null;

    // Identify which specific fields matched
    var matchedFields = [];
    var remarkTags = [];

    for (var i = 0; i < FIELD_PATTERNS.length; i++) {
      var fp = FIELD_PATTERNS[i];
      if (vigolium.utils.regexMatch(body, fp.regex)) {
        matchedFields.push(fp.id);
        remarkTags.push("verbose-json:" + fp.id);
      }
    }

    if (matchedFields.length === 0) return null;

    if (ctx.record && ctx.record.uuid) {
      ctx.record.addRemarks(remarkTags);
    }

    var description = "JSON response contains sensitive/verbose field names:\n" +
      matchedFields.map(function(f) { return "- `" + f + "`"; }).join("\n") +
      "\n\nThese fields may expose internal data, credentials, or debug information to API consumers.";

    return [{
      url: ctx.request ? ctx.request.url : "",
      matched: matchedFields.join(", "),
      name: "Verbose JSON Fields in Response",
      description: description,
      severity: "medium"
    }];
  }
};
