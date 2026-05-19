// response_size_anomaly.js
// Passive module: Detects response size anomalies by comparing the current
// response body length against a baseline median for the same path template.
// A response >= 10x the median (when median > 100 bytes) is flagged.

var MIN_RECORDS = 3;
var ANOMALY_MULTIPLIER = 10;
var MIN_MEDIAN = 100;

function computeMedian(values) {
  var sorted = values.slice().sort(function(a, b) { return a - b; });
  var mid = Math.floor(sorted.length / 2);
  if (sorted.length % 2 === 0) {
    return (sorted[mid - 1] + sorted[mid]) / 2;
  }
  return sorted[mid];
}

module.exports = {
  id: "response-size-anomaly",
  name: "Response Size Anomaly",
  description: "Detects responses whose body size is significantly larger than the baseline for the same path template",
  type: "passive",
  severity: "suspect",
  confidence: "tentative",
  scope: "response",
  tags: ["anomaly", "baseline", "light"],
  scanTypes: ["per_request"],

  scanPerRequest: function(ctx) {
    if (!ctx.response || !ctx.response.body) return null;
    if (!ctx.request || !ctx.request.url) return null;
    if (!vigolium.db || !vigolium.db.records) return null;

    var parsed = vigolium.parse.url(ctx.request.url);
    if (!parsed || !parsed.hostname) return null;

    var template = vigolium.utils.pathToTemplate(parsed.path || "/");
    var hostname = parsed.hostname;

    var records = vigolium.db.records.query({
      hostname: hostname,
      path: template,
      limit: 20
    });

    if (!records || records.length < MIN_RECORDS) return null;

    // Collect body lengths from historical records
    var lengths = [];
    for (var i = 0; i < records.length; i++) {
      if (records[i].response_length && records[i].response_length > 0) {
        lengths.push(records[i].response_length);
      }
    }

    if (lengths.length < MIN_RECORDS) return null;

    var median = computeMedian(lengths);
    if (median < MIN_MEDIAN) return null;

    var currentLength = ctx.response.body.length;
    if (currentLength < median * ANOMALY_MULTIPLIER) return null;

    var ratio = Math.round(currentLength / median);
    var remarkTags = ["response-size-anomaly"];

    if (ctx.record && ctx.record.uuid) {
      ctx.record.addRemarks(remarkTags);
    }

    var description = "Response body size (" + currentLength + " bytes) is " + ratio +
      "x larger than the median (" + Math.round(median) + " bytes) for path template `" +
      template + "` (based on " + lengths.length + " historical records).\n\n" +
      "This may indicate data exfiltration, verbose error output, or misconfigured endpoint.";

    return [{
      url: ctx.request.url,
      matched: "size=" + currentLength + " median=" + Math.round(median) + " ratio=" + ratio + "x",
      name: "Response Size Anomaly",
      description: description,
      severity: "suspect"
    }];
  }
};
