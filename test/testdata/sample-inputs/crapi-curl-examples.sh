#!/bin/bash
# crAPI (Completely Ridiculous API) - Curl Examples
# Base URL: http://localhost:8888
#
# Usage:
#   1. Set BASE_URL if your crAPI instance is not on localhost:8888
#   2. Set TOKEN after calling the login endpoint
#   3. Run individual commands or source this file and call functions
#
# Example:
#   export BASE_URL="http://localhost:8888"
#   export TOKEN="your-jwt-token-here"
#   ./crapi-curl-examples.sh

BASE_URL="${BASE_URL:-http://localhost:8888}"
TOKEN="${TOKEN:-your-jwt-token-here}"

###############################################################################
# Identity / Auth
###############################################################################

# 1. Sign Up
signup() {
  curl -s -X POST "${BASE_URL}/identity/api/auth/signup" \
    -H 'Content-Type: application/json' \
    -d '{
      "email": "Cristobal.Weissnat@example.com",
      "name": "Cristobal.Weissnat",
      "number": "6915656974",
      "password": "5hmb0gvyC__hVQg"
    }'
}

# 2. Login
login() {
  curl -s -X POST "${BASE_URL}/identity/api/auth/login" \
    -H 'Content-Type: application/json' \
    -d '{
      "email": "test@example.com",
      "password": "Test!123"
    }'
}

# 3. Forgot Password
forgot_password() {
  curl -s -X POST "${BASE_URL}/identity/api/auth/forget-password" \
    -H 'Content-Type: application/json' \
    -d '{
      "email": "adam007@example.com"
    }'
}

# 4. Check OTP - Version 3
check_otp_v3() {
  curl -s -X POST "${BASE_URL}/identity/api/auth/v3/check-otp" \
    -H 'Content-Type: application/json' \
    -d '{
      "email": "Cristobal.Weissnat@example.com",
      "otp": "9969",
      "password": "5hmb0gvyC__hVQg"
    }'
}

# 5. Check OTP - Version 2
check_otp_v2() {
  curl -s -X POST "${BASE_URL}/identity/api/auth/v2/check-otp" \
    -H 'Content-Type: application/json' \
    -d '{
      "email": "Cristobal.Weissnat@example.com",
      "otp": "9969",
      "password": "5hmb0gvyC__hVQg"
    }'
}

# 6. Login with Email Token - v4.0
login_with_token_v4() {
  curl -s -X POST "${BASE_URL}/identity/api/auth/v4.0/user/login-with-token" \
    -H 'Content-Type: application/json' \
    -d '{
      "email": "test@example.com",
      "token": "your-email-token-here"
    }'
}

# 7. Login with Email Token - v2.7
login_with_token_v2_7() {
  curl -s -X POST "${BASE_URL}/identity/api/auth/v2.7/user/login-with-token" \
    -H 'Content-Type: application/json' \
    -d '{
      "email": "test@example.com",
      "token": "your-email-token-here"
    }'
}

###############################################################################
# Identity / User
###############################################################################

# 8. Reset Password
reset_password() {
  curl -s -X POST "${BASE_URL}/identity/api/v2/user/reset-password" \
    -H 'Content-Type: application/json' \
    -H "Authorization: Bearer ${TOKEN}" \
    -d '{
      "email": "test@example.com",
      "password": "NewPassword123!"
    }'
}

# 9. Change Email
change_email() {
  curl -s -X POST "${BASE_URL}/identity/api/v2/user/change-email" \
    -H 'Content-Type: application/json' \
    -H "Authorization: Bearer ${TOKEN}" \
    -d '{
      "new_email": "Sofia.Predovic@example.com",
      "old_email": "Cristobal.Weissnat@example.com"
    }'
}

# 10. Verify Email Token
verify_email_token() {
  curl -s -X POST "${BASE_URL}/identity/api/v2/user/verify-email-token" \
    -H 'Content-Type: application/json' \
    -H "Authorization: Bearer ${TOKEN}" \
    -d '{
      "old_email": "Einar.Swaniawski@example.com",
      "new_email": "Danielle.Ankunding@example.com",
      "token": "T9O2s6i3C7o2E8l7X5Y4"
    }'
}

# 11. Get User Dashboard
get_dashboard() {
  curl -s -X GET "${BASE_URL}/identity/api/v2/user/dashboard" \
    -H "Authorization: Bearer ${TOKEN}"
}

# 12. Update Profile Picture
update_profile_pic() {
  local file="${1:-/path/to/profile-pic.jpg}"
  curl -s -X POST "${BASE_URL}/identity/api/v2/user/pictures" \
    -H "Authorization: Bearer ${TOKEN}" \
    -F "file=@${file}"
}

# 13. Upload Profile Video
upload_profile_video() {
  local file="${1:-/path/to/video.mp4}"
  curl -s -X POST "${BASE_URL}/identity/api/v2/user/videos" \
    -H "Authorization: Bearer ${TOKEN}" \
    -F "file=@${file}"
}

# 14. Get Profile Video
get_profile_video() {
  local video_id="${1:-1}"
  curl -s -X GET "${BASE_URL}/identity/api/v2/user/videos/${video_id}" \
    -H "Authorization: Bearer ${TOKEN}"
}

# 15. Update Profile Video
update_profile_video() {
  local video_id="${1:-10}"
  curl -s -X PUT "${BASE_URL}/identity/api/v2/user/videos/${video_id}" \
    -H 'Content-Type: application/json' \
    -H "Authorization: Bearer ${TOKEN}" \
    -d '{
      "id": '"${video_id}"',
      "videoName": "my-video.mp4",
      "video_url": "http://example.com/video.mp4",
      "conversion_params": "-v codec h264"
    }'
}

# 16. Delete Profile Video
delete_profile_video() {
  local video_id="${1:-1}"
  curl -s -X DELETE "${BASE_URL}/identity/api/v2/user/videos/${video_id}" \
    -H "Authorization: Bearer ${TOKEN}"
}

# 17. Convert Profile Video
convert_profile_video() {
  local video_id="${1:-1}"
  curl -s -X GET "${BASE_URL}/identity/api/v2/user/videos/convert_video?video_id=${video_id}" \
    -H "Authorization: Bearer ${TOKEN}"
}

###############################################################################
# Identity / Admin
###############################################################################

# 18. Delete Profile Video (Admin)
admin_delete_video() {
  local video_id="${1:-12345}"
  curl -s -X DELETE "${BASE_URL}/identity/api/v2/admin/videos/${video_id}" \
    -H "Authorization: Bearer ${TOKEN}"
}

###############################################################################
# Identity / Vehicle
###############################################################################

# 19. Get User Vehicles
get_vehicles() {
  curl -s -X GET "${BASE_URL}/identity/api/v2/vehicle/vehicles" \
    -H "Authorization: Bearer ${TOKEN}"
}

# 20. Add Vehicle
add_vehicle() {
  curl -s -X POST "${BASE_URL}/identity/api/v2/vehicle/add_vehicle" \
    -H 'Content-Type: application/json' \
    -H "Authorization: Bearer ${TOKEN}" \
    -d '{
      "pincode": "9896",
      "vin": "0IOJO38SMVL663989"
    }'
}

# 21. Get Vehicle Location
get_vehicle_location() {
  local vehicle_id="${1:-1929186d-8b67-4163-a208-de52a41f7301}"
  curl -s -X GET "${BASE_URL}/identity/api/v2/vehicle/${vehicle_id}/location" \
    -H "Authorization: Bearer ${TOKEN}"
}

# 22. Resend Vehicle Details Email
resend_vehicle_email() {
  curl -s -X POST "${BASE_URL}/identity/api/v2/vehicle/resend_email" \
    -H "Authorization: Bearer ${TOKEN}"
}

###############################################################################
# Community / Posts
###############################################################################

# 23. Get Post
get_post() {
  local post_id="${1:-tiSTSUzh4BwtvYSLWPsqu9}"
  curl -s -X GET "${BASE_URL}/community/api/v2/community/posts/${post_id}" \
    -H "Authorization: Bearer ${TOKEN}"
}

# 24. Create Post
create_post() {
  curl -s -X POST "${BASE_URL}/community/api/v2/community/posts" \
    -H 'Content-Type: application/json' \
    -H "Authorization: Bearer ${TOKEN}" \
    -d '{
      "title": "Velit quia minima.",
      "content": "Est maiores voluptas velit. Necessitatibus vero veniam quos nobis."
    }'
}

# 25. Post Comment
post_comment() {
  local post_id="${1:-tiSTSUzh4BwtvYSLWPsqu9}"
  curl -s -X POST "${BASE_URL}/community/api/v2/community/posts/${post_id}/comment" \
    -H 'Content-Type: application/json' \
    -H "Authorization: Bearer ${TOKEN}" \
    -d '{
      "content": "Porro aut ratione et."
    }'
}

# 26. Get Recent Posts
get_recent_posts() {
  local limit="${1:-30}"
  local offset="${2:-0}"
  curl -s -X GET "${BASE_URL}/community/api/v2/community/posts/recent?limit=${limit}&offset=${offset}" \
    -H "Authorization: Bearer ${TOKEN}"
}

###############################################################################
# Community / Coupon
###############################################################################

# 27. Add New Coupon
add_new_coupon() {
  curl -s -X POST "${BASE_URL}/community/api/v2/coupon/new-coupon" \
    -H 'Content-Type: application/json' \
    -H "Authorization: Bearer ${TOKEN}" \
    -d '{
      "coupon_code": "TRAC075",
      "amount": "75"
    }'
}

# 28. Validate Coupon
validate_coupon() {
  curl -s -X POST "${BASE_URL}/community/api/v2/coupon/validate-coupon" \
    -H 'Content-Type: application/json' \
    -H "Authorization: Bearer ${TOKEN}" \
    -d '{
      "coupon_code": "TRAC075"
    }'
}

###############################################################################
# Workshop / Shop
###############################################################################

# 29. Get Products
get_products() {
  curl -s -X GET "${BASE_URL}/workshop/api/shop/products" \
    -H "Authorization: Bearer ${TOKEN}"
}

# 30. Add New Product
add_new_product() {
  curl -s -X POST "${BASE_URL}/workshop/api/shop/products" \
    -H 'Content-Type: application/json' \
    -H "Authorization: Bearer ${TOKEN}" \
    -d '{
      "name": "WheelBase",
      "price": "10.12",
      "image_url": "http://example.com/wheelbase.png"
    }'
}

# 31. Create Order
create_order() {
  curl -s -X POST "${BASE_URL}/workshop/api/shop/orders" \
    -H 'Content-Type: application/json' \
    -H "Authorization: Bearer ${TOKEN}" \
    -d '{
      "product_id": 1,
      "quantity": 1
    }'
}

# 32. Get Order by ID
get_order() {
  local order_id="${1:-1}"
  curl -s -X GET "${BASE_URL}/workshop/api/shop/orders/${order_id}" \
    -H "Authorization: Bearer ${TOKEN}"
}

# 33. Update Order
update_order() {
  local order_id="${1:-1}"
  curl -s -X PUT "${BASE_URL}/workshop/api/shop/orders/${order_id}" \
    -H 'Content-Type: application/json' \
    -H "Authorization: Bearer ${TOKEN}" \
    -d '{
      "product_id": 1,
      "quantity": 2
    }'
}

# 34. Get All Orders
get_all_orders() {
  local limit="${1:-30}"
  local offset="${2:-0}"
  curl -s -X GET "${BASE_URL}/workshop/api/shop/orders/all?limit=${limit}&offset=${offset}" \
    -H "Authorization: Bearer ${TOKEN}"
}

# 35. Return Order
return_order() {
  local order_id="${1:-33}"
  curl -s -X POST "${BASE_URL}/workshop/api/shop/orders/return_order?order_id=${order_id}" \
    -H "Authorization: Bearer ${TOKEN}"
}

# 36. Apply Coupon
apply_coupon() {
  curl -s -X POST "${BASE_URL}/workshop/api/shop/apply_coupon" \
    -H 'Content-Type: application/json' \
    -H "Authorization: Bearer ${TOKEN}" \
    -d '{
      "coupon_code": "TRAC075",
      "amount": 75
    }'
}

# 37. Get Return QR Code
get_return_qr_code() {
  curl -s -X GET "${BASE_URL}/workshop/api/shop/return_qr_code" \
    -H 'Accept: */*' \
    --output qr_code.png
}

# 38. Get All Workshop Users
get_workshop_users() {
  local limit="${1:-30}"
  local offset="${2:-0}"
  curl -s -X GET "${BASE_URL}/workshop/api/management/users/all?limit=${limit}&offset=${offset}" \
    -H "Authorization: Bearer ${TOKEN}"
}

###############################################################################
# Workshop / Mechanic
###############################################################################

# 39. Get Mechanics
get_mechanics() {
  curl -s -X GET "${BASE_URL}/workshop/api/mechanic/" \
    -H "Authorization: Bearer ${TOKEN}"
}

# 40. Contact Mechanic
contact_mechanic() {
  curl -s -X POST "${BASE_URL}/workshop/api/merchant/contact_mechanic" \
    -H 'Content-Type: application/json' \
    -H "Authorization: Bearer ${TOKEN}" \
    -d '{
      "mechanic_api": "http://localhost:8000/workshop/api/mechanic/receive_report",
      "mechanic_code": "TRAC_JHN",
      "number_of_repeats": 1,
      "repeat_request_if_failed": false,
      "problem_details": "Hi Jhon",
      "vin": "8UOLV89RGKL908077"
    }'
}

# 41. Create Service Report (Receive Report)
receive_report() {
  local mechanic_code="${1:-TRAC_MECH1}"
  local problem_details="${2:-My car has engine trouble}"
  local vin="${3:-0BZCX25UTBJ987271}"
  curl -s -X GET "${BASE_URL}/workshop/api/mechanic/receive_report?mechanic_code=${mechanic_code}&problem_details=${problem_details}&vin=${vin}"
}

# 42. Get Service Report by ID
get_mechanic_report() {
  local report_id="${1:-2}"
  curl -s -X GET "${BASE_URL}/workshop/api/mechanic/mechanic_report?report_id=${report_id}" \
    -H "Authorization: Bearer ${TOKEN}"
}

# 43. Get Service Requests for Mechanic
get_service_requests() {
  local limit="${1:-30}"
  local offset="${2:-0}"
  curl -s -X GET "${BASE_URL}/workshop/api/mechanic/service_requests?limit=${limit}&offset=${offset}" \
    -H "Authorization: Bearer ${TOKEN}"
}

# 44. Mechanic Signup
mechanic_signup() {
  curl -s -X POST "${BASE_URL}/workshop/api/mechanic/signup" \
    -H 'Content-Type: application/json' \
    -d '{
      "name": "John Mechanic",
      "email": "john@workshop.com",
      "number": "4156789012",
      "password": "SecurePass123!",
      "mechanic_code": "TRAC_JHN"
    }'
}

###############################################################################
# Helper: Run all endpoints sequentially
###############################################################################

run_all() {
  echo "=== 1. Sign Up ==="
  signup
  echo -e "\n\n=== 2. Login ==="
  login
  echo -e "\n\n=== 3. Forgot Password ==="
  forgot_password
  echo -e "\n\n=== 4. Check OTP v3 ==="
  check_otp_v3
  echo -e "\n\n=== 5. Check OTP v2 ==="
  check_otp_v2
  echo -e "\n\n=== 6. Login with Token v4.0 ==="
  login_with_token_v4
  echo -e "\n\n=== 7. Login with Token v2.7 ==="
  login_with_token_v2_7
  echo -e "\n\n=== 8. Reset Password ==="
  reset_password
  echo -e "\n\n=== 9. Change Email ==="
  change_email
  echo -e "\n\n=== 10. Verify Email Token ==="
  verify_email_token
  echo -e "\n\n=== 11. Get Dashboard ==="
  get_dashboard
  echo -e "\n\n=== 14. Get Profile Video ==="
  get_profile_video
  echo -e "\n\n=== 17. Convert Profile Video ==="
  convert_profile_video
  echo -e "\n\n=== 19. Get Vehicles ==="
  get_vehicles
  echo -e "\n\n=== 20. Add Vehicle ==="
  add_vehicle
  echo -e "\n\n=== 21. Get Vehicle Location ==="
  get_vehicle_location
  echo -e "\n\n=== 22. Resend Vehicle Email ==="
  resend_vehicle_email
  echo -e "\n\n=== 23. Get Post ==="
  get_post
  echo -e "\n\n=== 24. Create Post ==="
  create_post
  echo -e "\n\n=== 25. Post Comment ==="
  post_comment
  echo -e "\n\n=== 26. Get Recent Posts ==="
  get_recent_posts
  echo -e "\n\n=== 27. Add New Coupon ==="
  add_new_coupon
  echo -e "\n\n=== 28. Validate Coupon ==="
  validate_coupon
  echo -e "\n\n=== 29. Get Products ==="
  get_products
  echo -e "\n\n=== 30. Add New Product ==="
  add_new_product
  echo -e "\n\n=== 31. Create Order ==="
  create_order
  echo -e "\n\n=== 32. Get Order ==="
  get_order
  echo -e "\n\n=== 33. Update Order ==="
  update_order
  echo -e "\n\n=== 34. Get All Orders ==="
  get_all_orders
  echo -e "\n\n=== 35. Return Order ==="
  return_order
  echo -e "\n\n=== 36. Apply Coupon ==="
  apply_coupon
  echo -e "\n\n=== 37. Get Return QR Code ==="
  get_return_qr_code
  echo -e "\n\n=== 38. Get Workshop Users ==="
  get_workshop_users
  echo -e "\n\n=== 39. Get Mechanics ==="
  get_mechanics
  echo -e "\n\n=== 40. Contact Mechanic ==="
  contact_mechanic
  echo -e "\n\n=== 41. Receive Report ==="
  receive_report
  echo -e "\n\n=== 42. Get Mechanic Report ==="
  get_mechanic_report
  echo -e "\n\n=== 43. Get Service Requests ==="
  get_service_requests
  echo -e "\n\n=== 44. Mechanic Signup ==="
  mechanic_signup
  echo -e "\n\nDone!"
}

# If script is executed (not sourced), run the specified function or show help
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  if [[ $# -gt 0 ]]; then
    "$@"
  else
    echo "crAPI Curl Examples"
    echo "==================="
    echo ""
    echo "Usage:"
    echo "  $0 <function_name> [args...]    Run a specific API call"
    echo "  $0 run_all                      Run all API calls sequentially"
    echo "  source $0                       Source the file to use functions interactively"
    echo ""
    echo "Environment variables:"
    echo "  BASE_URL  Base URL (default: http://localhost:8888)"
    echo "  TOKEN     JWT auth token (default: your-jwt-token-here)"
    echo ""
    echo "Available functions:"
    echo "  signup, login, forgot_password, check_otp_v3, check_otp_v2,"
    echo "  login_with_token_v4, login_with_token_v2_7, reset_password,"
    echo "  change_email, verify_email_token, get_dashboard, update_profile_pic,"
    echo "  upload_profile_video, get_profile_video, update_profile_video,"
    echo "  delete_profile_video, convert_profile_video, admin_delete_video,"
    echo "  get_vehicles, add_vehicle, get_vehicle_location, resend_vehicle_email,"
    echo "  get_post, create_post, post_comment, get_recent_posts,"
    echo "  add_new_coupon, validate_coupon, get_products, add_new_product,"
    echo "  create_order, get_order, update_order, get_all_orders, return_order,"
    echo "  apply_coupon, get_return_qr_code, get_workshop_users, get_mechanics,"
    echo "  contact_mechanic, receive_report, get_mechanic_report,"
    echo "  get_service_requests, mechanic_signup, run_all"
  fi
fi
