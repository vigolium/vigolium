// Test minified boolean conversion: !0 -> true, !1 -> false
fetch('/api/settings', {
  method: 'PUT',
  body: JSON.stringify({
    enabled: !0,
    disabled: !1,
    count: 123
  })
});

// Test with nested object
fetch('/api/config', {
  method: 'POST',
  body: JSON.stringify({
    features: {
      darkMode: !0,
      notifications: !1
    },
    active: !0
  })
});
