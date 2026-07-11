// Test: Object() Config Pattern (Vue.js/webpack environment config)
// Tests the Object({...}) pattern commonly found in bundled code

// Pattern 1: Object() wrapper (webpack environment injection)
var envConfig = Object({
    VUE_APP_API_URL: "https://api.example.com",
    VUE_APP_DEBUG: true,
    VUE_APP_VERSION: "3.0.0",
    VUE_APP_MAX_UPLOAD: 10485760
});

// Pattern 2: Direct Object() call
Object({
    REACT_APP_API_BASE: "https://backend.example.com/api/v2",
    REACT_APP_TIMEOUT: 30000,
    REACT_APP_RETRY: true
});

// API calls using these config values
fetch(envConfig.VUE_APP_API_URL + '/users', {
    method: 'GET'
});

fetch('/api/upload', {
    method: 'POST',
    body: JSON.stringify({
        maxSize: envConfig.VUE_APP_MAX_UPLOAD,
        debug: envConfig.VUE_APP_DEBUG,
        version: envConfig.VUE_APP_VERSION
    })
});
