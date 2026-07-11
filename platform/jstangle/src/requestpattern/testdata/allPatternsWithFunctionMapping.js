// Comprehensive test file for ALL request patterns with function mapping support
// Tests: nested function calls, inner functions, resolution contexts

// ============================================================================
// PATTERN 1: FETCH REQUEST - with function mapping
// ============================================================================

// Service with fetch inside
var FetchService = {
  getData: function(params) {
    fetch('/api/fetch-data', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Cookie': 'session=abc123'
      },
      body: JSON.stringify(params)
    });
  },
  getWithQuery: function(queryParams) {
    fetch('/api/fetch-query?' + new URLSearchParams(queryParams).toString());
  }
};

// Call sites for FetchService
function useFetchService() {
  var data = { userId: 100, action: 'load' };
  FetchService.getData(data);
}

// Inner function with fetch
function outerFetchWrapper() {
  function innerFetch(options) {
    fetch('/api/inner-fetch', {
      method: options.method,
      body: JSON.stringify(options.data)
    });
  }

  var opts = { method: 'PUT', data: { id: 999, name: 'test' } };
  innerFetch(opts);
}

// ============================================================================
// PATTERN 2: XHR REQUEST - needs function mapping support
// ============================================================================

// Service with XMLHttpRequest
var XHRService = {
  sendRequest: function(endpoint, params) {
    var xhr = new XMLHttpRequest();
    xhr.open('POST', endpoint);
    xhr.setRequestHeader('Content-Type', 'application/json');
    xhr.send(JSON.stringify(params));
  }
};

// Call site for XHR
function useXHRService() {
  var requestParams = { apiKey: 'key123', query: 'search' };
  XHRService.sendRequest('/api/xhr-endpoint', requestParams);
}

// ============================================================================
// PATTERN 3: JQUERY AJAX - needs function mapping support
// ============================================================================

// Angular-style service with jQuery ajax
angular.module('jqueryApp')
  .factory('AjaxService', function() {
    return {
      fetchData: function(config) {
        $.ajax({
          url: '/api/jquery-ajax',
          type: 'POST',
          data: config.data,
          headers: config.headers
        });
      },
      getData: function(params) {
        $.ajax({
          url: '/api/jquery-get',
          type: 'GET',
          data: params
        });
      }
    };
  });

// Call sites for AjaxService
function useAjaxService() {
  var ajaxConfig = {
    data: { itemId: 500, category: 'electronics' },
    headers: { 'X-Custom': 'value' }
  };
  AjaxService.fetchData(ajaxConfig);
}

function searchWithAjax() {
  var searchParams = { q: 'laptop', limit: 10, offset: 0 };
  AjaxService.getData(searchParams);
}

// ============================================================================
// PATTERN 4: JQUERY METHOD ($.get, $.post) - needs function mapping support
// ============================================================================

var JQueryMethodService = {
  loadData: function(id, filters) {
    $.get('/api/jquery-method/' + id, filters);
  },
  saveData: function(payload) {
    $.post('/api/jquery-save', payload);
  },
  updateData: function(id, data) {
    $.put('/api/jquery-update/' + id, JSON.stringify(data));
  }
};

// Call sites
function useJQueryMethodService() {
  var filterObj = { status: 'active', sort: 'date' };
  JQueryMethodService.loadData(123, filterObj);

  var savePayload = { name: 'New Item', price: 99.99 };
  JQueryMethodService.saveData(savePayload);
}

// ============================================================================
// PATTERN 5: GENERIC REQUEST PATTERN 1 - func(method, url, ...) or func(url, method, ...)
// ============================================================================

var GenericPattern1Service = {
  callEndpoint: function(params) {
    this.apiClient.callApi('/api/generic1-endpoint', 'GET', {}, {}, params, {}, null);
  },
  postData: function(body) {
    return this.apiClient.callApi('POST', '/api/generic1-post', {}, {}, body, {}, null);
  }
};

// Call sites
function useGenericPattern1() {
  var queryParams = { page: 1, size: 20 };
  GenericPattern1Service.callEndpoint(queryParams);

  var postBody = { title: 'Hello', content: 'World' };
  GenericPattern1Service.postData(postBody);
}

// ============================================================================
// PATTERN 6: GENERIC REQUEST PATTERN 2 - obj.get(url), obj.post(url, data)
// ============================================================================

var GenericPattern2Service = {
  fetchItems: function(filters) {
    return httpClient.get('/api/generic2-items', { params: filters });
  },
  createItem: function(itemData) {
    return httpClient.post('/api/generic2-create', { data: itemData });
  },
  updateItem: function(id, changes) {
    return httpClient.put('/api/generic2-update/' + id, { data: changes });
  }
};

// Call sites
function useGenericPattern2() {
  var filterData = { category: 'books', inStock: true };
  GenericPattern2Service.fetchItems(filterData);

  var newItem = { name: 'New Book', author: 'John Doe' };
  GenericPattern2Service.createItem(newItem);
}

// ============================================================================
// PATTERN 7: GENERIC REQUEST PATTERN 3 - { url: '...', method: '...' }
// ============================================================================

angular.module('configApp')
  .factory('ConfigService', function($http) {
    return {
      loadConfig: function(params) {
        return $http({
          url: '/api/generic3-config',
          method: 'GET',
          params: params,
          headers: {
            'Authorization': 'Bearer token123'
          }
        });
      },
      saveConfig: function(configData) {
        return $http({
          url: '/api/generic3-save',
          method: 'POST',
          data: configData,
          cookies: {
            session_id: 'sess_456'
          }
        });
      }
    };
  });

// Call sites
function useConfigService() {
  var loadParams = { env: 'production', version: '2.0' };
  ConfigService.loadConfig(loadParams);

  var saveData = { theme: 'dark', language: 'en' };
  ConfigService.saveConfig(saveData);
}

// ============================================================================
// PATTERN 8: GENERIC REQUEST PATTERN 4 - any function with URL string
// ============================================================================

var GenericPattern4Service = {
  navigate: function(destination, context) {
    openUrl('/api/generic4-navigate', context, { rawUri: true });
  },
  redirect: function(target, params) {
    (0, utils.navigate)('/api/generic4-redirect', params);
  }
};

// Call sites
function useGenericPattern4() {
  var navContext = { source: 'menu', target: 'dashboard' };
  GenericPattern4Service.navigate('/dashboard', navContext);

  var redirectParams = { returnUrl: '/home', timeout: 5000 };
  GenericPattern4Service.redirect('/login', redirectParams);
}

// ============================================================================
// PATTERN 9: VARIABLE CONTAINS URL - with function mapping
// ============================================================================

var VariableURLService = {
  loadResource: function(resourceParams) {
    var apiUrl = '/api/variable-url-resource';
    makeRequest(apiUrl, 'GET', {}, {}, resourceParams);
  },
  submitForm: function(formData) {
    var submitUrl = '/api/variable-url-submit';
    sendData(submitUrl, 'POST', {}, {}, JSON.stringify(formData));
  }
};

// Call sites
function useVariableURLService() {
  var resourceQuery = { resourceId: 'res_001', format: 'json' };
  VariableURLService.loadResource(resourceQuery);

  var formInput = { email: 'test@example.com', subscribe: true };
  VariableURLService.submitForm(formInput);
}

// ============================================================================
// COMPLEX NESTED SCENARIOS
// ============================================================================

// Deeply nested function calls (3 levels)
angular.module('nestedApp')
  .factory('Level1Service', function($http) {
    return {
      level1Method: function(p1) {
        return $http({ url: '/api/nested-level1', method: 'GET', params: p1 });
      }
    };
  })
  .factory('Level2Service', function(Level1Service) {
    return {
      level2Method: function(p2) {
        return Level1Service.level1Method(p2);
      }
    };
  })
  .factory('Level3Service', function(Level2Service) {
    return {
      level3Method: function(p3) {
        return Level2Service.level2Method(p3);
      }
    };
  });

// Call site for deeply nested
function useNestedServices() {
  var deepParams = { level: 3, data: 'deeply-nested' };
  Level3Service.level3Method(deepParams);
}

// Inner function inside member expression assignment
function setupInnerFunctions() {
  var controller = {};

  controller.fetchAll = function(criteria) {
    $.ajax({
      url: '/api/inner-member-ajax',
      type: 'GET',
      data: criteria
    });
  };

  controller.saveAll = function(items) {
    fetch('/api/inner-member-fetch', {
      method: 'POST',
      body: JSON.stringify(items)
    });
  };

  // Call sites for inner functions
  var searchCriteria = { status: 'pending', priority: 'high' };
  controller.fetchAll(searchCriteria);

  var itemsToSave = [{ id: 1, name: 'Item 1' }, { id: 2, name: 'Item 2' }];
  controller.saveAll(itemsToSave);
}

// Multiple call sites for same function
var MultiCallService = {
  apiCall: function(endpoint, params) {
    return $http({ url: endpoint, method: 'GET', params: params });
  }
};

// Multiple different call sites
function callSite1() {
  MultiCallService.apiCall('/api/endpoint1', { source: 'callSite1' });
}

function callSite2() {
  MultiCallService.apiCall('/api/endpoint2', { source: 'callSite2', extra: 'data' });
}

function callSite3() {
  var dynamicParams = {};
  dynamicParams.source = 'callSite3';
  dynamicParams.timestamp = Date.now();
  MultiCallService.apiCall('/api/endpoint3', dynamicParams);
}
