// add_auth_header.js
// Pre-hook: Injects an Authorization header (from config variable) and
// a custom correlation ID into every outgoing request.

module.exports = {
  id: "add-auth-header",
  name: "Auth Header Injector",
  description: "Adds Authorization and X-Correlation-ID headers to every request",
  type: "pre_hook",
  tags: ["auth", "headers"],

  execute: function(request) {
    var token = vigolium.config.auth_token || "";
    if (token === "") {
      // No token configured, pass through unchanged
      return request;
    }

    var correlationId = vigolium.utils.randomString(12);

    return {
      headers: {
        "Authorization": "Bearer " + token,
        "X-Correlation-ID": correlationId
      }
    };
  }
};
