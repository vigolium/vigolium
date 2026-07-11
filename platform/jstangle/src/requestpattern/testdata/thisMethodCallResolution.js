// Test case for this.methodName() resolution with returned object templates
// Pattern: JSON.stringify(this.prepareRecord(params)) should resolve to actual object structure
//
// This tests:
// 1. A helper method that returns an object using parameters
// 2. Another method that calls this.helperMethod() inside JSON.stringify()
// 3. The returned object template substitution with resolved params from call sites

angular.module('logApp')
  .factory('LogService', ['$http', '$rootScope', function ($http, $rootScope) {
    var api = {
      // Helper method that returns an object template
      // Called as: this.prepareRecord(viewId) inside saveView
      prepareRecord: function(viewId) {
        var json = {
          globalId: $rootScope.globalId,
          ctdType: 'VIEW',
          contentId: viewId,
          brandId: $rootScope.currentBrand.brandId,
          timestamp: new Date().getTime()
        };
        return json;
      },

      // Method that uses this.prepareRecord inside JSON.stringify
      saveView: function(viewId) {
        var jsonRecord = JSON.stringify(this.prepareRecord(viewId));
        return $http({
          url: '/api/log/view',
          method: 'POST',
          data: jsonRecord
        });
      },

      // Another helper for audit records
      prepareAuditRecord: function(action, resourceId) {
        return {
          action: action,
          resourceId: resourceId,
          userId: $rootScope.userId,
          auditTimestamp: new Date().toISOString()
        };
      },

      // Uses prepareAuditRecord
      saveAudit: function(action, resourceId) {
        return $http({
          url: '/api/audit',
          method: 'POST',
          data: JSON.stringify(this.prepareAuditRecord(action, resourceId))
        });
      },

      // Simple method with direct params (for comparison)
      directPost: function(data) {
        return $http({
          url: '/api/direct',
          method: 'POST',
          data: JSON.stringify(data)
        });
      }
    };
    return api;
  }]);

// Call sites for saveView - should resolve viewId in the returned object
function onViewPage() {
  LogService.saveView('page-123');
}

function onViewDocument() {
  LogService.saveView('doc-456');
}

// Call sites for saveAudit - should resolve action and resourceId
function onCreateResource() {
  LogService.saveAudit('CREATE', 'resource-001');
}

function onDeleteResource() {
  LogService.saveAudit('DELETE', 'resource-002');
}

// Call site for directPost - simple case for comparison
function submitData() {
  var formData = { name: 'test', value: 123 };
  LogService.directPost(formData);
}
