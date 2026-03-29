# Auth Workflows

Detailed patterns for capturing authentication state with `agent-browser` and feeding it to vigolium.

## Form-Based Login (Username/Password)

The most common pattern. Open the login page, snapshot to find form fields, fill and submit.

```bash
# Open and snapshot
agent-browser open https://example.com/login --session-name app
agent-browser snapshot --json --session-name app

# Typical snapshot output (abbreviated):
# @e10 textbox "Username or email"
# @e14 textbox "Password" (type=password)
# @e18 button "Log in"

# Fill credentials and submit
agent-browser fill @e10 "testuser@example.com" --session-name app
agent-browser fill @e14 "P@ssw0rd!" --session-name app
agent-browser click @e18 --session-name app

# Wait for login to complete
agent-browser wait --url "*/dashboard*" --session-name app

# Extract cookies
agent-browser cookies --session-name app --json
```

### Detecting Login Success

Three strategies to confirm the login succeeded:

```bash
# 1. URL change (redirect to dashboard/home)
agent-browser wait --url "*/dashboard*" --timeout 10s --session-name app

# 2. Element presence (logged-in indicator)
agent-browser wait "#user-menu" --timeout 10s --session-name app

# 3. Text presence (welcome message)
agent-browser wait --text "Welcome back" --timeout 10s --session-name app
```

If none of these match within the timeout, the login likely failed. Re-snapshot to check for error messages:

```bash
agent-browser snapshot --json --session-name app
# Look for: @e25 text "Invalid credentials"
```

## OAuth Redirect Flows

OAuth flows involve redirects through an identity provider. The browser follows the full redirect chain automatically.

```bash
# Start the OAuth flow
agent-browser open https://myapp.com/auth/google --session-name oauth

# Snapshot the Google login page
agent-browser snapshot --json --session-name oauth
# @e8 textbox "Email or phone"
# @e12 button "Next"

# Enter email
agent-browser fill @e8 "user@gmail.com" --session-name oauth
agent-browser click @e12 --session-name oauth

# Wait for password page
agent-browser wait "input[type=password]" --timeout 10s --session-name oauth
agent-browser snapshot --json --session-name oauth
# @e15 textbox "Enter your password"
# @e20 button "Next"

agent-browser fill @e15 "password123" --session-name oauth
agent-browser click @e20 --session-name oauth

# Wait for consent screen (if applicable)
agent-browser wait --text "wants to access" --timeout 10s --session-name oauth
agent-browser snapshot --json --session-name oauth
# @e30 button "Allow"
agent-browser click @e30 --session-name oauth

# Wait for redirect back to the app
agent-browser wait --url "*/myapp.com/*" --timeout 15s --session-name oauth

# Capture the final session cookies
agent-browser cookies --session-name oauth --json
```

## JWT Token Capture from localStorage

Many SPAs store JWT tokens in `localStorage` or `sessionStorage` after login.

```bash
# Complete login flow first (form-based or OAuth)
# ...

# Extract JWT from localStorage
agent-browser storage local get --key auth_token --session-name app
# Output: eyJhbGciOiJIUzI1NiIs...

# Common key names to check
agent-browser storage local get --key token --session-name app
agent-browser storage local get --key access_token --session-name app
agent-browser storage local get --key id_token --session-name app
agent-browser storage local get --key jwt --session-name app

# Or dump all localStorage to find the right key
agent-browser storage local --session-name app --json

# Use the token with vigolium
TOKEN=$(agent-browser storage local get --key auth_token --session-name app)
vigolium scan -t https://example.com --header "Authorization: Bearer $TOKEN"
```

For tokens in `sessionStorage`:

```bash
agent-browser storage session get --key auth_token --session-name app
```

## Cookie Extraction and Vigolium Auth Config

### Extract Cookies

```bash
# All cookies as JSON
agent-browser cookies --session-name app --json

# Cookies for a specific domain
agent-browser cookies --session-name app --domain example.com --json

# Cookies formatted as a Cookie header value
agent-browser cookies --session-name app --format header
# Output: session_id=abc123; csrf_token=xyz789; _ga=GA1.2.123456
```

### Convert to Vigolium Auth Config

Create an `auth-config.yaml` from extracted cookies:

```yaml
sessions:
  - name: browser_captured
    role: primary
    headers:
      Cookie: "session_id=abc123; csrf_token=xyz789"
```

For token-based auth:

```yaml
sessions:
  - name: browser_captured
    role: primary
    headers:
      Authorization: "Bearer eyJhbGciOiJIUzI1NiIs..."
```

For both cookie and token:

```yaml
sessions:
  - name: browser_captured
    role: primary
    headers:
      Cookie: "session_id=abc123"
      Authorization: "Bearer eyJhbGciOiJIUzI1NiIs..."
      X-CSRF-Token: "xyz789"
```

Use with vigolium:

```bash
vigolium scan -t https://example.com --auth-config auth-config.yaml
```

## Multi-Step Flows (MFA Handling)

Some login flows require multiple pages: password, then MFA code.

```bash
# Step 1: Username/password (same as form-based)
agent-browser open https://example.com/login --session-name mfa
agent-browser snapshot --json --session-name mfa
agent-browser fill @e10 "admin@example.com" --session-name mfa
agent-browser fill @e14 "P@ssw0rd!" --session-name mfa
agent-browser click @e18 --session-name mfa

# Step 2: MFA page
agent-browser wait --text "verification code" --timeout 10s --session-name mfa
agent-browser snapshot --json --session-name mfa
# @e22 textbox "Enter 6-digit code"
# @e26 button "Verify"

# If using TOTP, generate code externally or from vault
agent-browser fill @e22 "123456" --session-name mfa
agent-browser click @e26 --session-name mfa

# Step 3: Confirm login completed
agent-browser wait --url "*/dashboard*" --timeout 10s --session-name mfa

# Extract session
agent-browser cookies --session-name mfa --json
```

### Handling "Remember This Device" Prompts

```bash
# After MFA verification, a "trust this device" prompt may appear
agent-browser wait --text "Trust this" --timeout 5s --session-name mfa
agent-browser snapshot --json --session-name mfa
# @e30 button "Yes, trust this device"
agent-browser click @e30 --session-name mfa
```

## CSRF Token Extraction

Some apps embed CSRF tokens in the page or in cookies. Extract them for use in scan headers.

```bash
# From a meta tag
agent-browser eval "document.querySelector('meta[name=csrf-token]').content" --session-name app
# Output: abc123xyz

# From a hidden form field
agent-browser eval "document.querySelector('input[name=_csrf]').value" --session-name app

# From a cookie
agent-browser cookies --session-name app --json
# Filter for csrf-related cookies in the output
```
