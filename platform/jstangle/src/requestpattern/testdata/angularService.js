// Angular service with function mapping test case
angular.module('myApp')
  .factory('UserService', function ($http) {
    var api = {
      getUser: function(params) {
        return $http({ url: '/api/user', method: 'GET', params: params });
      },
      createUser: function(data) {
        return $http({ url: '/api/user', method: 'POST', data: data });
      },
      updateUser: function(id, data) {
        return $http({ url: '/api/user/' + id, method: 'PUT', data: data });
      }
    };
    return api;
  });

// Call sites with resolved values
function loadUser() {
  var params = { userId: 123 };
  UserService.getUser(params);
}

function createNewUser() {
  var userData = {
    name: 'John',
    email: 'john@example.com'
  };
  UserService.createUser(userData);
}

// Call site with inline object
UserService.updateUser(456, { name: 'Jane', role: 'admin' });

// Call site with variable built from property assignments
function searchUsers() {
  var params = {};
  params.query = 'test';
  params.limit = 10;
  params.page = 1;
  UserService.getUser(params);
}
