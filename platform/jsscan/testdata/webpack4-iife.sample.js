/*
 * Synthetic Webpack 4 IIFE bundle fixture.
 *
 * Hand-written, deliberately minimal sample used by the webpack extractor
 * tests. It reproduces the classic Webpack 4 runtime shape — an IIFE wrapping
 * a module array — so the extractor can recognise modules and HTTP calls
 * without shipping real third-party site bundles. Not produced by any build
 * tool; safe to regenerate by hand.
 */
(function (modules) {
  var installedModules = {};
  function __webpack_require__(moduleId) {
    if (installedModules[moduleId]) {
      return installedModules[moduleId].exports;
    }
    var module = (installedModules[moduleId] = {
      i: moduleId,
      l: false,
      exports: {},
    });
    modules[moduleId].call(
      module.exports,
      module,
      module.exports,
      __webpack_require__
    );
    module.l = true;
    return module.exports;
  }
  __webpack_require__.s = 0;
  return __webpack_require__(0);
})([
  function (module, exports, __webpack_require__) {
    "use strict";
    var api = __webpack_require__(1);
    api.fetchUsers("/api/users");
    api.createUser("/api/users", { name: "demo" });
  },
  function (module, exports) {
    "use strict";
    module.exports = {
      fetchUsers: function (url) {
        return fetch(url, { method: "GET" });
      },
      createUser: function (url, body) {
        return fetch(url, { method: "POST", body: JSON.stringify(body) });
      },
    };
  },
]);
