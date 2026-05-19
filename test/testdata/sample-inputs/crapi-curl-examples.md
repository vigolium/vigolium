# crAPI (Completely Ridiculous API) - Curl Examples

Base URL: `http://localhost:8888`

> **Note:** Replace `{{TOKEN}}` with a valid JWT token obtained from the login endpoint.

---

## Identity / Auth

### 1. Sign Up

```bash
curl -X POST http://localhost:8888/identity/api/auth/signup \
  -H 'Content-Type: application/json' \
  -d '{
    "email": "Cristobal.Weissnat@example.com",
    "name": "Cristobal.Weissnat",
    "number": "6915656974",
    "password": "5hmb0gvyC__hVQg"
  }'
```

### 2. Login

```bash
curl -X POST http://localhost:8888/identity/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{
    "email": "test@example.com",
    "password": "Test!123"
  }'
```

### 3. Forgot Password

```bash
curl -X POST http://localhost:8888/identity/api/auth/forget-password \
  -H 'Content-Type: application/json' \
  -d '{
    "email": "adam007@example.com"
  }'
```

### 4. Check OTP - Version 3

```bash
curl -X POST http://localhost:8888/identity/api/auth/v3/check-otp \
  -H 'Content-Type: application/json' \
  -d '{
    "email": "Cristobal.Weissnat@example.com",
    "otp": "9969",
    "password": "5hmb0gvyC__hVQg"
  }'
```

### 5. Check OTP - Version 2

```bash
curl -X POST http://localhost:8888/identity/api/auth/v2/check-otp \
  -H 'Content-Type: application/json' \
  -d '{
    "email": "Cristobal.Weissnat@example.com",
    "otp": "9969",
    "password": "5hmb0gvyC__hVQg"
  }'
```

### 6. Login with Email Token - v4.0

```bash
curl -X POST http://localhost:8888/identity/api/auth/v4.0/user/login-with-token \
  -H 'Content-Type: application/json' \
  -d '{
    "email": "test@example.com",
    "token": "your-email-token-here"
  }'
```

### 7. Login with Email Token - v2.7

```bash
curl -X POST http://localhost:8888/identity/api/auth/v2.7/user/login-with-token \
  -H 'Content-Type: application/json' \
  -d '{
    "email": "test@example.com",
    "token": "your-email-token-here"
  }'
```

---

## Identity / User

### 8. Reset Password

```bash
curl -X POST http://localhost:8888/identity/api/v2/user/reset-password \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer {{TOKEN}}' \
  -d '{
    "email": "test@example.com",
    "password": "NewPassword123!"
  }'
```

### 9. Change Email

```bash
curl -X POST http://localhost:8888/identity/api/v2/user/change-email \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer {{TOKEN}}' \
  -d '{
    "new_email": "Sofia.Predovic@example.com",
    "old_email": "Cristobal.Weissnat@example.com"
  }'
```

### 10. Verify Email Token

```bash
curl -X POST http://localhost:8888/identity/api/v2/user/verify-email-token \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer {{TOKEN}}' \
  -d '{
    "old_email": "Einar.Swaniawski@example.com",
    "new_email": "Danielle.Ankunding@example.com",
    "token": "T9O2s6i3C7o2E8l7X5Y4"
  }'
```

### 11. Get User Dashboard

```bash
curl -X GET http://localhost:8888/identity/api/v2/user/dashboard \
  -H 'Authorization: Bearer {{TOKEN}}'
```

### 12. Update Profile Picture

```bash
curl -X POST http://localhost:8888/identity/api/v2/user/pictures \
  -H 'Authorization: Bearer {{TOKEN}}' \
  -F 'file=@/path/to/profile-pic.jpg'
```

### 13. Upload Profile Video

```bash
curl -X POST http://localhost:8888/identity/api/v2/user/videos \
  -H 'Authorization: Bearer {{TOKEN}}' \
  -F 'file=@/path/to/video.mp4'
```

### 14. Get Profile Video

```bash
curl -X GET http://localhost:8888/identity/api/v2/user/videos/1 \
  -H 'Authorization: Bearer {{TOKEN}}'
```

### 15. Update Profile Video

```bash
curl -X PUT http://localhost:8888/identity/api/v2/user/videos/10 \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer {{TOKEN}}' \
  -d '{
    "id": 10,
    "videoName": "my-video.mp4",
    "video_url": "http://example.com/video.mp4",
    "conversion_params": "-v codec h264"
  }'
```

### 16. Delete Profile Video

```bash
curl -X DELETE http://localhost:8888/identity/api/v2/user/videos/1 \
  -H 'Authorization: Bearer {{TOKEN}}'
```

### 17. Convert Profile Video

```bash
curl -X GET 'http://localhost:8888/identity/api/v2/user/videos/convert_video?video_id=1' \
  -H 'Authorization: Bearer {{TOKEN}}'
```

---

## Identity / Admin

### 18. Delete Profile Video (Admin)

```bash
curl -X DELETE http://localhost:8888/identity/api/v2/admin/videos/12345 \
  -H 'Authorization: Bearer {{TOKEN}}'
```

---

## Identity / Vehicle

### 19. Get User Vehicles

```bash
curl -X GET http://localhost:8888/identity/api/v2/vehicle/vehicles \
  -H 'Authorization: Bearer {{TOKEN}}'
```

### 20. Add Vehicle

```bash
curl -X POST http://localhost:8888/identity/api/v2/vehicle/add_vehicle \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer {{TOKEN}}' \
  -d '{
    "pincode": "9896",
    "vin": "0IOJO38SMVL663989"
  }'
```

### 21. Get Vehicle Location

```bash
curl -X GET http://localhost:8888/identity/api/v2/vehicle/1929186d-8b67-4163-a208-de52a41f7301/location \
  -H 'Authorization: Bearer {{TOKEN}}'
```

### 22. Resend Vehicle Details Email

```bash
curl -X POST http://localhost:8888/identity/api/v2/vehicle/resend_email \
  -H 'Authorization: Bearer {{TOKEN}}'
```

---

## Community / Posts

### 23. Get Post

```bash
curl -X GET http://localhost:8888/community/api/v2/community/posts/tiSTSUzh4BwtvYSLWPsqu9 \
  -H 'Authorization: Bearer {{TOKEN}}'
```

### 24. Create Post

```bash
curl -X POST http://localhost:8888/community/api/v2/community/posts \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer {{TOKEN}}' \
  -d '{
    "title": "Velit quia minima.",
    "content": "Est maiores voluptas velit. Necessitatibus vero veniam quos nobis."
  }'
```

### 25. Post Comment

```bash
curl -X POST http://localhost:8888/community/api/v2/community/posts/tiSTSUzh4BwtvYSLWPsqu9/comment \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer {{TOKEN}}' \
  -d '{
    "content": "Porro aut ratione et."
  }'
```

### 26. Get Recent Posts

```bash
curl -X GET 'http://localhost:8888/community/api/v2/community/posts/recent?limit=30&offset=0' \
  -H 'Authorization: Bearer {{TOKEN}}'
```

---

## Community / Coupon

### 27. Add New Coupon

```bash
curl -X POST http://localhost:8888/community/api/v2/coupon/new-coupon \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer {{TOKEN}}' \
  -d '{
    "coupon_code": "TRAC075",
    "amount": "75"
  }'
```

### 28. Validate Coupon

```bash
curl -X POST http://localhost:8888/community/api/v2/coupon/validate-coupon \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer {{TOKEN}}' \
  -d '{
    "coupon_code": "TRAC075"
  }'
```

---

## Workshop / Shop

### 29. Get Products

```bash
curl -X GET http://localhost:8888/workshop/api/shop/products \
  -H 'Authorization: Bearer {{TOKEN}}'
```

### 30. Add New Product

```bash
curl -X POST http://localhost:8888/workshop/api/shop/products \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer {{TOKEN}}' \
  -d '{
    "name": "WheelBase",
    "price": "10.12",
    "image_url": "http://example.com/wheelbase.png"
  }'
```

### 31. Create Order

```bash
curl -X POST http://localhost:8888/workshop/api/shop/orders \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer {{TOKEN}}' \
  -d '{
    "product_id": 1,
    "quantity": 1
  }'
```

### 32. Get Order by ID

```bash
curl -X GET http://localhost:8888/workshop/api/shop/orders/1 \
  -H 'Authorization: Bearer {{TOKEN}}'
```

### 33. Update Order

```bash
curl -X PUT http://localhost:8888/workshop/api/shop/orders/1 \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer {{TOKEN}}' \
  -d '{
    "product_id": 1,
    "quantity": 2
  }'
```

### 34. Get All Orders

```bash
curl -X GET 'http://localhost:8888/workshop/api/shop/orders/all?limit=30&offset=0' \
  -H 'Authorization: Bearer {{TOKEN}}'
```

### 35. Return Order

```bash
curl -X POST 'http://localhost:8888/workshop/api/shop/orders/return_order?order_id=33' \
  -H 'Authorization: Bearer {{TOKEN}}'
```

### 36. Apply Coupon

```bash
curl -X POST http://localhost:8888/workshop/api/shop/apply_coupon \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer {{TOKEN}}' \
  -d '{
    "coupon_code": "TRAC075",
    "amount": 75
  }'
```

### 37. Get Return QR Code

```bash
curl -X GET http://localhost:8888/workshop/api/shop/return_qr_code \
  -H 'Accept: */*' \
  --output qr_code.png
```

### 38. Get All Workshop Users

```bash
curl -X GET 'http://localhost:8888/workshop/api/management/users/all?limit=30&offset=0' \
  -H 'Authorization: Bearer {{TOKEN}}'
```

---

## Workshop / Mechanic

### 39. Get Mechanics

```bash
curl -X GET http://localhost:8888/workshop/api/mechanic/ \
  -H 'Authorization: Bearer {{TOKEN}}'
```

### 40. Contact Mechanic

```bash
curl -X POST http://localhost:8888/workshop/api/merchant/contact_mechanic \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer {{TOKEN}}' \
  -d '{
    "mechanic_api": "http://localhost:8000/workshop/api/mechanic/receive_report",
    "mechanic_code": "TRAC_JHN",
    "number_of_repeats": 1,
    "repeat_request_if_failed": false,
    "problem_details": "Hi Jhon",
    "vin": "8UOLV89RGKL908077"
  }'
```

### 41. Create Service Report (Receive Report)

```bash
curl -X GET 'http://localhost:8888/workshop/api/mechanic/receive_report?mechanic_code=TRAC_MECH1&problem_details=My+car+has+engine+trouble%2C+and+I+need+urgent+help!&vin=0BZCX25UTBJ987271'
```

### 42. Get Service Report by ID

```bash
curl -X GET 'http://localhost:8888/workshop/api/mechanic/mechanic_report?report_id=2' \
  -H 'Authorization: Bearer {{TOKEN}}'
```

### 43. Get Service Requests for Mechanic

```bash
curl -X GET 'http://localhost:8888/workshop/api/mechanic/service_requests?limit=30&offset=0' \
  -H 'Authorization: Bearer {{TOKEN}}'
```

### 44. Mechanic Signup

```bash
curl -X POST http://localhost:8888/workshop/api/mechanic/signup \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "John Mechanic",
    "email": "john@workshop.com",
    "number": "4156789012",
    "password": "SecurePass123!",
    "mechanic_code": "TRAC_JHN"
  }'
```
