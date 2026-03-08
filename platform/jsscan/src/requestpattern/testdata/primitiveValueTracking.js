// Test: Primitive Value Tracking - All types (string, number, boolean)
// This tests that non-URL primitive values are resolved correctly

// Numeric config values
var MAX_RETRIES = 3;
var TIMEOUT_MS = 5000;
var PAGE_SIZE = 20;

// Boolean config values
var DEBUG_MODE = true;
var CACHE_ENABLED = false;

// String config values (non-URL)
var APP_NAME = "MyApp";
var VERSION = "1.2.3";

// API calls using tracked variables
fetch('/api/config', {
    method: 'POST',
    body: JSON.stringify({
        retries: MAX_RETRIES,
        timeout: TIMEOUT_MS,
        pageSize: PAGE_SIZE,
        debug: DEBUG_MODE,
        cache: CACHE_ENABLED,
        appName: APP_NAME,
        version: VERSION
    })
});

// URL with tracked variables
fetch('/api/data?limit=' + PAGE_SIZE + '&retries=' + MAX_RETRIES);
