// sensitive_data_exposure.js
// Passive module: Detects PII and sensitive data patterns in HTTP response
// bodies that the built-in secret-detect (API keys/tokens) does not
// cover — credit cards, SSNs, internal IPs, private keys, phone numbers, and
// bulk email addresses.

var RULES = [
  {
    id: "credit-card-visa",
    label: "Credit Card (Visa)",
    regex: "\\b4[0-9]{12}(?:[0-9]{3})?\\b"
  },
  {
    id: "credit-card-mastercard",
    label: "Credit Card (Mastercard)",
    regex: "\\b5[1-5][0-9]{14}\\b"
  },
  {
    id: "credit-card-amex",
    label: "Credit Card (Amex)",
    regex: "\\b3[47][0-9]{13}\\b"
  },
  {
    id: "ssn",
    label: "Social Security Number",
    regex: "\\b[0-9]{3}-[0-9]{2}-[0-9]{4}\\b"
  },
  {
    id: "internal-ip",
    label: "Internal IPv4 Address",
    regex: "\\b(?:10\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}|172\\.(?:1[6-9]|2\\d|3[01])\\.\\d{1,3}\\.\\d{1,3}|192\\.168\\.\\d{1,3}\\.\\d{1,3})\\b"
  },
  {
    id: "private-key",
    label: "Private Key",
    regex: "-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"
  },
  {
    id: "aws-key",
    label: "AWS Access Key",
    regex: "\\bAKIA[0-9A-Z]{16}\\b"
  },
  {
    id: "phone-us",
    label: "US Phone Number",
    regex: "\\b(?:\\+1[-.\\s]?)?\\(?[0-9]{3}\\)?[-.\\s][0-9]{3}[-.\\s][0-9]{4}\\b"
  }
];

// Threshold for bulk email detection
var EMAIL_REGEX = "[A-Za-z0-9._%+\\-]+@[A-Za-z0-9.\\-]+\\.[A-Za-z]{2,}";
var BULK_EMAIL_THRESHOLD = 5;

// Content types to skip (JS, CSS, images produce false positives)
var SKIP_CONTENT_TYPES = ["javascript", "css", "image/"];

function shouldSkip(contentType) {
  if (!contentType) return false;
  var ct = contentType.toLowerCase();
  for (var i = 0; i < SKIP_CONTENT_TYPES.length; i++) {
    if (ct.indexOf(SKIP_CONTENT_TYPES[i]) !== -1) return true;
  }
  return false;
}

module.exports = {
  id: "sensitive-data-exposure",
  name: "Sensitive Data Exposure in Response",
  description: "Detects PII and sensitive data patterns (credit cards, SSNs, internal IPs, private keys, phone numbers) in HTTP response bodies",
  type: "passive",
  severity: "suspect",
  confidence: "tentative",
  scope: "response",
  tags: ["pii", "exposure", "sensitive-data", "light"],
  scanTypes: ["per_request"],

  scanPerRequest: function(ctx) {
    if (!ctx.response || !ctx.response.body) return null;

    // Skip responses with content types that produce false positives
    var contentType = ctx.response.headers ? ctx.response.headers["content-type"] || "" : "";
    if (shouldSkip(contentType)) return null;

    var body = ctx.response.body;
    var matchedCategories = [];
    var remarkTags = [];

    // Check each rule
    for (var i = 0; i < RULES.length; i++) {
      var rule = RULES[i];
      if (vigolium.utils.regexMatch(body, rule.regex)) {
        matchedCategories.push("- **" + rule.label + "**");
        remarkTags.push("sensitive-data:" + rule.id);
      }
    }

    // Check for bulk email addresses
    var emailMatches = vigolium.utils.regexFindAll(body, EMAIL_REGEX);
    if (emailMatches && emailMatches.length >= BULK_EMAIL_THRESHOLD) {
      // Deduplicate
      var seen = {};
      var unique = 0;
      for (var j = 0; j < emailMatches.length; j++) {
        var e = emailMatches[j].toLowerCase();
        if (!seen[e]) {
          seen[e] = true;
          unique++;
        }
      }
      if (unique >= BULK_EMAIL_THRESHOLD) {
        matchedCategories.push("- **Bulk Email Addresses** (" + unique + " unique)");
        remarkTags.push("sensitive-data:bulk-email");
      }
    }

    if (matchedCategories.length === 0) return null;

    // Annotate the HTTP record if available
    if (ctx.record && ctx.record.uuid) {
      ctx.record.addRemarks(remarkTags);
    }

    var description = "The response body contains patterns matching sensitive data categories:\n" +
      matchedCategories.join("\n") +
      "\n\nManual review is recommended to confirm these are real data exposures and not false positives (e.g. documentation examples, test data).";

    return [{
      url: ctx.request ? ctx.request.url : "",
      matched: remarkTags.join(", "),
      name: "Sensitive Data Exposure in Response",
      description: description,
      severity: "suspect"
    }];
  }
};
