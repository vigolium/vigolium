// Test: Generic Variable Name Filtering
// Tests that generic names (id, key, name, etc.) are NOT tracked globally
// to avoid false positive resolutions

// These should NOT be tracked (generic names)
var id = "should-not-track";
var key = "should-not-track";
var name = "should-not-track";
var value = "should-not-track";
var data = "should-not-track";
var type = "should-not-track";

// These SHOULD be tracked (specific names >= 2 chars)
var userId = "user-123";
var apiKey = "secret-key-456";
var userName = "john_doe";

// Single char names should NOT be tracked (minified)
var a = "no-track-a";
var b = "no-track-b";
var t = "no-track-t";
var e = "no-track-e";

// API calls - generic names should remain as ${...}
fetch('/api/items/' + id + '/details', {
    method: 'GET'
});

// Specific names should be resolved
fetch('/api/users/' + userId, {
    method: 'GET',
    headers: {
        'X-Api-Key': apiKey,
        'X-User': userName
    }
});

// Body with mixed - generic stays as placeholder
fetch('/api/save', {
    method: 'POST',
    body: JSON.stringify({
        userId: userId,
        id: id,
        name: name,
        userName: userName
    })
});
