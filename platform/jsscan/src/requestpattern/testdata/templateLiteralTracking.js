// Test: Template Literal Tracking
// Tests that simple template literals (no expressions) are tracked

// Simple template literals (should be tracked)
var apiEndpoint = `/api/v2`;
var servicePath = `/services/auth`;
var configKey = `app-config-key`;
var versionStr = `v1.0.0`;

// Template literals with expressions (should NOT be tracked as-is)
var dynamicPath = `/api/users/${someId}`;

// Numbers and booleans with template
var maxCount = `100`;  // string "100", not number
var isDebug = `true`;  // string "true", not boolean

// API calls using tracked template literals
fetch(apiEndpoint + '/data', {
    method: 'GET'
});

fetch(servicePath + '/login', {
    method: 'POST',
    body: JSON.stringify({
        key: configKey,
        version: versionStr
    })
});

// Mixed usage
fetch('/api/config', {
    method: 'PUT',
    body: JSON.stringify({
        endpoint: apiEndpoint,
        path: servicePath,
        maxCount: maxCount,
        debug: isDebug
    })
});
