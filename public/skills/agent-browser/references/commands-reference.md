# Commands Reference

Complete command index for `agent-browser`, organized by category.

## Navigation

```bash
agent-browser open <url>                    # Navigate to URL
agent-browser open <url> --session-name s1  # Navigate within a named session
agent-browser open <url> --wait load        # Wait for load event before returning
agent-browser open <url> --wait networkidle # Wait for network idle

agent-browser back                          # Go back in history
agent-browser forward                       # Go forward in history
agent-browser reload                        # Reload current page
agent-browser close                         # Close browser/session
agent-browser close --session-name s1       # Close a specific session
```

## Interaction

All interaction commands accept `@e<N>` refs from `snapshot --json` or CSS/XPath selectors.

```bash
# Click
agent-browser click @e15                    # Left-click element
agent-browser dblclick @e15                 # Double-click element
agent-browser click @e15 --button right     # Right-click

# Text input
agent-browser fill @e10 "value"             # Clear field, then type value
agent-browser type @e10 "value"             # Type without clearing (appends)
agent-browser press Enter                   # Press a keyboard key
agent-browser press Control+a               # Key combination

# Hover and select
agent-browser hover @e20                    # Hover over element
agent-browser select @e25 "option-value"    # Select dropdown option by value
agent-browser select @e25 --label "Option"  # Select by visible label

# Checkboxes
agent-browser check @e30                    # Check a checkbox
agent-browser uncheck @e30                  # Uncheck a checkbox

# Scroll
agent-browser scroll down                   # Scroll page down
agent-browser scroll up                     # Scroll page up
agent-browser scroll @e40                   # Scroll element into view

# Drag and drop
agent-browser drag @e10 @e20               # Drag from source to target

# File upload
agent-browser upload @e35 /path/to/file.pdf # Upload file to input element
```

## Observation

```bash
# Accessibility tree snapshot
agent-browser snapshot                      # Human-readable text snapshot
agent-browser snapshot --json               # Structured JSON with @e refs
agent-browser snapshot -i                   # Interactive elements only

# Screenshots
agent-browser screenshot                    # Capture to stdout (PNG)
agent-browser screenshot -o page.png        # Save to file
agent-browser screenshot --annotate         # Overlay @e refs on elements
agent-browser screenshot --full-page        # Capture entire scrollable page
agent-browser screenshot @e15 -o elem.png   # Screenshot a specific element

# PDF export
agent-browser pdf -o page.pdf              # Save page as PDF

# JavaScript evaluation
agent-browser eval "document.title"         # Execute JS, return result
agent-browser eval "window.location.href"   # Get current URL via JS
agent-browser eval --file script.js         # Execute JS from file
```

## Data Extraction

```bash
# Get element/page data
agent-browser get text @e15                 # Inner text of element
agent-browser get html @e15                 # Inner HTML of element
agent-browser get value @e10                # Value of input element
agent-browser get attr @e15 href            # Attribute value
agent-browser get title                     # Page title
agent-browser get url                       # Current page URL
agent-browser get count "li.item"           # Count matching elements
```

## Element State

```bash
agent-browser is visible @e15               # Check if element is visible
agent-browser is enabled @e10               # Check if element is enabled
agent-browser is checked @e30               # Check if checkbox is checked
```

## Wait

```bash
# Wait for element
agent-browser wait "#dashboard"             # Wait for selector to appear
agent-browser wait @e15                     # Wait for ref to appear
agent-browser wait "#dashboard" --timeout 10s

# Wait for conditions
agent-browser wait --text "Welcome"         # Wait for text to appear on page
agent-browser wait --url "*/dashboard*"     # Wait for URL to match glob
agent-browser wait --load                   # Wait for page load event
agent-browser wait --fn "() => document.readyState === 'complete'"  # Custom JS predicate
```

## Network

```bash
# Route interception
agent-browser network route "*/api/flags" --body '{"debug":true}'      # Mock response
agent-browser network route "*/api/flags" --status 500                 # Force error
agent-browser network route "*/analytics*" --abort                     # Block request
agent-browser network route "*/api/*" --header "X-Test: true"          # Add header

# Traffic capture
agent-browser network requests                   # List captured requests
agent-browser network requests --json            # JSON format
agent-browser network har -o traffic.har         # Export as HAR file
```

## Cookies

```bash
agent-browser cookies                            # List all cookies
agent-browser cookies --json                     # JSON format
agent-browser cookies --domain example.com       # Filter by domain
agent-browser cookies --format header            # As Cookie header value

agent-browser cookies set name=value domain=example.com  # Set a cookie
agent-browser cookies clear                      # Clear all cookies
agent-browser cookies clear --domain example.com # Clear cookies for domain
```

## Storage

```bash
# localStorage
agent-browser storage local --json               # Dump all localStorage
agent-browser storage local get --key auth_token  # Get specific key
agent-browser storage local set --key foo --value bar  # Set key
agent-browser storage local clear                # Clear all localStorage

# sessionStorage
agent-browser storage session --json             # Dump all sessionStorage
agent-browser storage session get --key token    # Get specific key
agent-browser storage session set --key foo --value bar
agent-browser storage session clear
```

## Auth Vault

```bash
agent-browser auth save <name> --url <login-url> --username <user>  # Save credentials
agent-browser auth save <name> --url <url> --username <user> --password-env VAR
agent-browser auth login <name> --session-name s1   # Replay saved login flow
agent-browser auth list                             # List vault entries
agent-browser auth delete <name>                    # Remove vault entry
```

## State Management

```bash
agent-browser state save --session-name s1 --state file.json   # Export state
agent-browser state load --state file.json --session-name s2   # Import state
agent-browser state list                                       # List state files
agent-browser state show --state file.json                     # Inspect state file
agent-browser state clean --older-than 7d                      # Remove old state files
agent-browser state clean --all                                # Remove all state files
agent-browser state clean --expired                            # Remove expired sessions
```

## Sessions

```bash
agent-browser session list                  # List active sessions
agent-browser close --session-name s1       # Close session
```

## Batch Execution

Run multiple commands in a single call. Useful for scripting and reducing round-trips.

```bash
agent-browser batch --json '[
  {"cmd": "open", "args": ["https://example.com/login"]},
  {"cmd": "snapshot", "args": ["--json"]},
  {"cmd": "fill", "args": ["@e10", "admin"]},
  {"cmd": "fill", "args": ["@e14", "password"]},
  {"cmd": "click", "args": ["@e18"]},
  {"cmd": "wait", "args": ["--url", "*/dashboard*"]},
  {"cmd": "cookies", "args": ["--json"]}
]'
```

Commands execute sequentially. If a command fails, subsequent commands are skipped unless `--continue-on-error` is set.

## Global Flags

| Flag | Description |
|------|-------------|
| `--session-name` | Named session for state persistence across commands |
| `--profile` | Chrome user data directory for full browser state persistence |
| `--json` | Structured JSON output |
| `--timeout` | Command timeout (default: 30s) |
| `--headless` | Run headless (default: true, use `--headless=false` for visible browser) |
| `--auto-connect` | Attach to running Chrome on debugging port |
| `--viewport` | Browser viewport size (e.g., `1920x1080`) |
| `--user-agent` | Custom User-Agent string |
| `--proxy` | HTTP/SOCKS5 proxy for browser traffic |
| `--vault-key` | Master key for auth vault encryption |
| `--verbose` | Verbose logging |
