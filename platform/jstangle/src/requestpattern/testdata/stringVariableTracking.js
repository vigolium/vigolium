// Test: String Variable Tracking (non-URL strings)
// Tests that non-URL string values are tracked and resolved

// Application strings
var appVersion = "2.5.1";
var buildNumber = "build-12345";
var environment = "production";

// User-related strings
var defaultRole = "user";
var adminRole = "admin";
var guestRole = "guest";

// Configuration strings
var logLevel = "INFO";
var dateFormat = "YYYY-MM-DD";
var locale = "en-US";

// Object with string properties
var appConfig = {
    name: "MyApplication",
    region: "us-east-1",
    tier: "premium"
};

// API calls with string values
fetch('/api/info', {
    method: 'POST',
    body: JSON.stringify({
        version: appVersion,
        build: buildNumber,
        env: environment
    })
});

// Header-style usage
fetch('/api/users', {
    method: 'GET',
    headers: {
        'X-App-Version': appVersion,
        'X-Environment': environment
    }
});

// Role-based body
fetch('/api/roles/assign', {
    method: 'POST',
    body: JSON.stringify({
        defaultRole: defaultRole,
        adminRole: adminRole,
        guestRole: guestRole
    })
});

// Object property usage
fetch('/api/app/config', {
    method: 'PUT',
    body: JSON.stringify({
        appName: appConfig.name,
        region: appConfig.region,
        tier: appConfig.tier,
        logLevel: logLevel,
        locale: locale
    })
});
