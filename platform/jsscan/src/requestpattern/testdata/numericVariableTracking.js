// Test: Numeric Variable Tracking
// Tests that numeric variables are tracked and resolved in API calls

// Integer values
var userId = 12345;
var categoryId = 42;
var offset = 0;
var limit = 100;

// Float values
var price = 19.99;
var taxRate = 0.08;

// Negative and zero
var minValue = -100;
var zeroValue = 0;

// Object with numeric properties
var config = {
    maxItems: 500,
    minAge: 18,
    defaultScore: 75
};

// API calls with numeric values
fetch('/api/users/' + userId + '/categories/' + categoryId);

fetch('/api/products', {
    method: 'GET'
});

// Query params with numbers
fetch('/api/items?offset=' + offset + '&limit=' + limit);

// POST with numeric body
fetch('/api/cart', {
    method: 'POST',
    body: JSON.stringify({
        itemId: userId,
        quantity: limit,
        price: price,
        tax: taxRate
    })
});

// Using object properties
fetch('/api/config', {
    method: 'PUT',
    body: JSON.stringify({
        maxItems: config.maxItems,
        minAge: config.minAge,
        score: config.defaultScore
    })
});
