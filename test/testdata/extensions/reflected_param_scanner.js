// reflected_param_scanner.js
// Active module: Detects user input reflected in HTTP responses.
// Injects a unique canary into each insertion point and checks whether
// the response body contains the canary string verbatim.

module.exports = {
  id: "reflected-param",
  name: "Reflected Parameter Scanner",
  description: "Injects a canary value into each parameter and checks if the response reflects it back",
  type: "active",
  severity: "medium",
  confidence: "firm",
  tags: ["xss", "reflection", "injection"],
  scanTypes: ["per_insertion_point"],

  scanPerInsertionPoint: function(ctx, insertion) {
    var canary = "VGNM" + vigolium.utils.randomString(8);
    var built = insertion.buildRequest(canary);
    var resp = vigolium.http.send(built);

    if (!resp || !resp.body) return null;

    if (resp.body.indexOf(canary) !== -1) {
      return [{
        matched: canary,
        url: ctx.request.url,
        name: "Reflected parameter: " + insertion.name,
        description: "The value of parameter '" + insertion.name + "' is reflected in the response body without encoding",
        severity: "medium"
      }];
    }
    return null;
  }
};
