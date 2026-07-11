// Test: Boolean Variable Tracking
// Tests boolean variables including minified (!0, !1) and regular (true, false)

// Regular booleans
var isEnabled = true;
var isDisabled = false;

// Minified booleans (common in webpack bundles)
var isActive = !0;    // true
var isInactive = !1;  // false

// Object with boolean properties
var settings = {
    darkMode: true,
    notifications: false,
    autoSave: !0,
    offlineMode: !1
};

// API calls with boolean values
fetch('/api/features', {
    method: 'POST',
    body: JSON.stringify({
        enabled: isEnabled,
        disabled: isDisabled,
        active: isActive,
        inactive: isInactive
    })
});

// Using object booleans
fetch('/api/user/settings', {
    method: 'PUT',
    body: JSON.stringify({
        darkMode: settings.darkMode,
        notifications: settings.notifications,
        autoSave: settings.autoSave,
        offlineMode: settings.offlineMode
    })
});

// Mixed with other types
fetch('/api/config/update', {
    method: 'PATCH',
    body: JSON.stringify({
        featureEnabled: isEnabled,
        count: 42,
        name: "config"
    })
});
