// Test: Assignment Expression Tracking
// Tests that assignments (a = "value") are tracked properly

var apiBase;
var maxItems;
var isProduction;

// Simple assignments
apiBase = "/api/v1";
maxItems = 50;
isProduction = true;

// Member expression assignments
var config = {};
config.endpoint = "/services/data";
config.timeout = 10000;
config.retry = false;

// Re-assignment (should keep first value)
var baseUrl = "/initial";
baseUrl = "/should-not-override";

// API calls using assigned values
fetch(apiBase + '/users', {
    method: 'GET'
});

fetch(config.endpoint + '/query', {
    method: 'POST',
    body: JSON.stringify({
        limit: maxItems,
        production: isProduction,
        timeout: config.timeout,
        retry: config.retry
    })
});

fetch(baseUrl + '/test');
