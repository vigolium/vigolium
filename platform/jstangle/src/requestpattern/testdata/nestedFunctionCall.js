// Test case for nested function call resolution
// fillDownloads wraps CommentsService.getComments

angular.module('myApp')
  .factory('CommentsService', function ($http) {
    var api = {
      getComments: function(params) {
        // This is the HTTP request that should get resolved params from fillDownloads
        return $http({ url: '/api/comments', method: 'GET', params: params });
      }
    };
    return api;
  })
  .factory('DataService', function (CommentsService) {
    var api = {
      fillDownloads: function(params, index) {
        // Nested call - params comes from fillDownloads caller
        CommentsService.getComments(params);
      }
    };
    return api;
  });

// Call site for fillDownloads with resolved params
function loadData() {
  var myParams = { contentId: 123, category: 'news' };
  DataService.fillDownloads(myParams, 0);
}

// Another call site with different params
function loadOtherData() {
  var otherParams = { contentId: 456, type: 'article' };
  DataService.fillDownloads(otherParams, 1);
}
