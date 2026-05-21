# CSRF Testing Checklist
> Derived from ~30 real-world vulnerability cases (WooYun 2010-2016)

## High-Risk Parameters to Test
| Parameter | Context |
|-----------|---------|
| `formhash` | Forum/CMS anti-CSRF tokens (often decorative) |
| `callback` | JSONP endpoints |
| `action` | State-changing operations |
| `uid`, `touid` | User targeting in social features |
| `newPassword` | Password change forms |
| `email` | Account binding/unbinding |
| `nickname`, `sex`, `year` | Profile modification |
| `status`, `content` | Post/comment creation |

## Common Attack Patterns
1. **No token validation** (most common) - State-changing requests lack CSRF tokens entirely
2. **GET-based state changes** - Follow, post, profile edit via GET requests exploitable with `<img>` tags
3. **Decorative tokens** - Token present in form but server never validates it
4. **Missing Referer check** - No origin verification on POST requests
5. **Token not bound to session** - Any valid token works for any user
6. **OAuth binding CSRF** - Third-party account binding lacks `state` parameter

## High-Impact CSRF Targets
- Password/email change (account takeover chain)
- OAuth account binding (hijack via CSRF)
- Admin panel operations (password change without old password verification)
- Payment address modification
- Social actions (follow, post, comment) for worm propagation

## Bypass Techniques
- **GET fallback**: POST endpoints that also accept GET requests
- **Referer stripping**: Use `<meta name="referrer" content="no-referrer">`
- **Subdomain trust**: Referer check only validates partial domain match
- **Flash/XMLHttpRequest**: Cross-origin requests with `withCredentials: true`
- **Token reuse**: Same token valid across sessions or users

## Quick Test Vectors
```html
<!-- Basic form auto-submit -->
<form action="TARGET_URL" method="POST" id="csrf">
  <input type="hidden" name="param" value="value"/>
</form>
<script>document.getElementById('csrf').submit();</script>

<!-- GET-based via image tag -->
<img src="https://target.com/action?param=value"/>

<!-- XMLHttpRequest with credentials -->
<script>
var x = new XMLHttpRequest();
x.open("POST", "TARGET_URL", true);
x.withCredentials = true;
x.setRequestHeader("Content-Type",
  "application/x-www-form-urlencoded");
x.send("param=value");
</script>
```

## Testing Methodology
1. Identify all state-changing endpoints (POST and GET)
2. Check for CSRF tokens in requests
3. Remove/modify token and replay -- does it still succeed?
4. Check if GET method is accepted for POST endpoints
5. Test Referer header removal and spoofing
6. Verify token is bound to current session
7. Test OAuth flows for missing `state` parameter

## Common Root Causes
- Developer trusts frontend to prevent duplicate submissions
- Token added to form HTML but never validated server-side
- Reliance on Referer header (easily stripped)
- GET endpoints for state-changing operations
- No re-authentication for sensitive operations (password change)
