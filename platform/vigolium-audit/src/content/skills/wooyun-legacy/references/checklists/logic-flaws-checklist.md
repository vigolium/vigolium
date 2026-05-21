# Logic Flaws Testing Checklist
> Derived from ~85 real-world vulnerability cases (WooYun 2010-2016)

## High-Risk Parameters to Test
| Parameter | Context |
|-----------|---------|
| `code`, `validatecode` | SMS/email verification codes |
| `password`, `newPwd` | Password reset flows |
| `sign`, `timestamp` | Request signing mechanisms |
| `v`, `from` | Version/source parameters |
| `adultNum`, `childNum` | Quantity fields in orders |
| `amount`, `price` | Payment amounts |
| `token`, `newMobile` | Session/binding tokens |
| `flag`, `phone` | Password recovery flow control |

## Common Attack Patterns (by frequency)
1. **Arbitrary password reset** (most common)
   - Verification code leaked in response
   - Short/numeric verification codes (4-digit) with no rate limiting
   - Verification not bound to phone/account
   - Client-side verification bypass (modify response)
2. **Payment amount tampering**
   - Price sent in client request, not validated server-side
   - Negative quantity to reduce total
   - Race condition in cart/checkout flow
3. **SMS/verification code abuse**
   - No rate limit on code sending (SMS bombing)
   - No expiration on verification codes
   - Code reuse across different operations
4. **Authorization bypass (IDOR)**
   - Sequential user/order IDs enable enumeration
   - Delete/modify operations lack ownership check
5. **Client-side trust**
   - JavaScript validation only, no server-side check
   - Response manipulation to bypass checks

## Bypass Techniques
- **Response tampering**: Intercept and change server response (e.g., `false` to `true`)
- **Verification code brute-force**: 4-digit codes = 10,000 attempts, often no lockout
- **Base64 encoded codes**: Decode, enumerate, re-encode
- **Negative values**: Set quantity to `-1` to create credit
- **Step skipping**: Jump directly to final step of multi-step process
- **Parameter pollution**: Submit same parameter twice with different values
- **IP spoofing**: `X-Forwarded-For` to bypass IP-based restrictions

## Quick Test Vectors
```
# Password reset - verify code in response
1. Initiate reset, capture response
2. Check if verification code appears in JSON/HTML response

# Brute-force short verification codes
POST /verify?phone=TARGET&code=FUZZ
# Fuzz 0000-9999 with no rate limiting

# Payment tampering
# Original: amount=19900 (199.00)
# Modified: amount=1 (0.01)

# Negative quantity
# Original: count=1
# Modified: count=-1

# Skip verification step
# Go directly to /reset/step3 without completing step2

# Response manipulation
# Change {"result":"fail"} to {"result":"success"}
```

## Testing Methodology
1. Map all multi-step flows (registration, password reset, payment)
2. Test each step independently -- can steps be skipped?
3. Check if verification codes appear in responses
4. Test rate limiting on verification endpoints
5. Attempt parameter tampering on price/quantity fields
6. Verify server-side validation matches client-side
7. Check IDOR on all endpoints with user/object IDs
8. Test for race conditions on balance/inventory operations

## High-Impact Targets
- Password reset/recovery flows
- Payment and checkout processes
- SMS verification endpoints
- Account binding (email, phone, OAuth)
- Admin operations without re-authentication
- Coupon/discount redemption

## Common Root Causes
- Verification logic in client-side JavaScript only
- Verification codes returned in API responses
- No rate limiting on authentication attempts
- Price/amount accepted from client without server-side recalculation
- Sequential predictable IDs without authorization checks
- Multi-step processes that don't validate completion of prior steps
