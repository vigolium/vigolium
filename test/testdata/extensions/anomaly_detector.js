// anomaly_detector.js — Active module that detects anomalous responses
// Sends the same request multiple times and flags statistical outliers

module.exports = {
  id: "anomaly-detector",
  name: "Response Anomaly Detector",
  type: "active",
  severity: "info",
  description: "Sends duplicate requests and detects anomalous responses",
  tags: ["anomaly", "active"],
  scanTypes: ["per_request"],

  scanPerRequest: function(ctx) {
    var responses = [];

    // Send the same request 5 times
    for (var i = 0; i < 5; i++) {
      var resp = vigolium.http.send(ctx.request.raw);
      if (resp) {
        responses.push({
          status: resp.status,
          body: resp.body,
          headers: resp.headers
        });
      }
      vigolium.utils.sleep(100);
    }

    if (responses.length < 2) return null;

    var ranked = vigolium.utils.detectAnomaly(responses);
    var results = [];

    for (var j = 0; j < ranked.length; j++) {
      var entry = ranked[j];
      if (entry.score > 5000) {
        results.push({
          url: ctx.request.url,
          name: "Response Anomaly Detected",
          severity: "info",
          description: "Response #" + entry.index + " scored " + entry.score + " (anomalous behavior detected)"
        });
      }
    }

    return results.length > 0 ? results : null;
  }
};
