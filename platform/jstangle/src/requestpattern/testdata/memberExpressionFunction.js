// Test case for member expression function assignments
// Pattern: scope.methodName = function(params) { ... }
// This is common in Angular directives/controllers

angular.module('myApp')
  .factory('CommentsService', function ($http) {
    var api = {
      getComments: function(params) {
        return $http({ url: '/api/comments', method: 'GET', params: params });
      }
    };
    return api;
  })
  .directive('resourceList', function (CommentsService) {
    return {
      link: function (scope) {
        // Member expression function assignment - nested wrapper
        scope.fillDownloads = function(params, index) {
          CommentsService.getComments(params);
        };

        // Call fillDownloads with params built from property assignments
        var params = {};
        params.contentId = scope.resourceFiles[0].id;
        params.currentUserName = 'testUser';
        scope.fillDownloads(params, 0);
      }
    };
  });

// Also test fetch inside member expression function
function externalLoad() {
  var resourceScope = {};

  // This defines the function on resourceScope
  resourceScope.loadData = function(params) {
    fetch('/api/load', {
      method: 'POST',
      body: JSON.stringify(params)
    });
  };

  // Call with resolved params
  var loadParams = { resourceId: 456, action: 'refresh' };
  resourceScope.loadData(loadParams);
}
