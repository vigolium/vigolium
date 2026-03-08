// error_pattern_detector.js
// Active module: Sends common error-triggering payloads per-request and
// checks whether the response contains stack traces or debug messages.

module.exports = {
  id: "error-pattern-detector",
  name: "Error Pattern Detector",
  description: "Detects error messages and stack traces in HTTP responses that may reveal internal details",
  type: "active",
  severity: "low",
  confidence: "firm",
  tags: ["error-handling", "information-disclosure", "light"],
  scanTypes: ["per_request"],

  scanPerRequest: function(ctx) {
    if (!ctx.response || !ctx.response.body) return null;

    var body = ctx.response.body;
    var findings = [];

    var patterns = [
      { regex: /Traceback \(most recent call last\)/i, name: "Python traceback" },
      { regex: /at [A-Za-z0-9_.$]+\.(java|kt):\d+/i, name: "Java/Kotlin stack trace" },
      { regex: /goroutine \d+ \[running\]/i, name: "Go panic stack trace" },
      { regex: /SQLSTATE\[/i, name: "SQL error (SQLSTATE)" },
      { regex: /mysql_fetch|pg_query|sqlite3?\./i, name: "Database function leak" },
      { regex: /Fatal error:.*on line \d+/i, name: "PHP fatal error" },
      { regex: /Microsoft OLE DB Provider/i, name: "ASP/OLE DB error" }
    ];

    for (var i = 0; i < patterns.length; i++) {
      if (patterns[i].regex.test(body)) {
        findings.push({
          matched: patterns[i].name,
          url: ctx.request.url,
          name: "Error pattern: " + patterns[i].name,
          description: "Response body contains a " + patterns[i].name + " which may reveal internal details",
          severity: "low"
        });
      }
    }

    return findings.length > 0 ? findings : null;
  }
};
