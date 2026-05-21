# Command Execution Testing Checklist
> Derived from 57 real-world vulnerability cases (WooYun 2010-2016)

## High-Risk Parameters to Test
| Parameter | Frequency | Notes |
|-----------|-----------|-------|
| `from` | 1x | Login redirect; deserialization entry |
| `param` | 1x | Generic parameter in SAP/enterprise systems |
| `action` / `module` | 2x | MVC dispatch parameters |
| `addr` | 1x | Network address inputs (ping/traceroute) |
| `itemId` | 1x | Item lookup triggering backend processing |
| `pwd` / `pwpwd` | 2x | Authentication parameters |
| `authenticationEntry` | 1x | Spring Security entry point |
| `siteroot` | 1x | Configuration parameters |

## Attack Pattern Distribution
| Pattern | Count | Percentage |
|---------|-------|------------|
| Direct command execution | 38 | 67% |
| Getshell via RCE | 9 | 16% |
| Information leakage chain | 5 | 9% |
| Deserialization to RCE | 5 | 9% |

## Vulnerability Sources (ranked by frequency)

### 1. Apache Struts2 OGNL Injection (~45% of cases)
The single most common command execution vector in the dataset.
- S2-045, S2-046, S2-048, S2-052 and related CVEs
- Targets: `.action` and `.do` URL endpoints
- Detection: Look for `struts2` in response headers or URL patterns

**Test indicators:**
```
/login.action
/index.do
/upload.action
Content-Type: %{...}  (S2-045)
```

### 2. Java Deserialization (~20% of cases)
- JBoss JMXInvokerServlet / EJBInvokerServlet
- WebLogic T3 protocol
- Jenkins CLI
- Spring Framework

**Test endpoints:**
```
/invoker/JMXInvokerServlet
/invoker/EJBInvokerServlet
/jmx-console/
/web-console/
```

### 3. Middleware Misconfiguration (~15% of cases)
- JBoss default deployment consoles
- Resin admin panel exposed
- WebLogic console with default credentials
- Tomcat manager with weak auth

### 4. Application-Level Command Injection (~10% of cases)
- SAP systems: `EXECUTE_CMD;CMDLINE=cmd.exe%20/c%20...`
- Network management tools with ping/traceroute functions
- Monitoring systems executing OS commands

### 5. PHP Code Execution (~10% of cases)
- `eval()` with user-controlled input
- Unsafe `unserialize()`
- Template injection

## Common Exploitation Payloads

### Struts2 OGNL
```
%{(#context['com.opensymphony.xwork2.dispatcher.
  HttpServletResponse'].getWriter().println('test'))}

redirect:${#context...}
```

### JBoss Deserialization
```
POST /invoker/JMXInvokerServlet HTTP/1.1
[serialized Java object payload]
```

### OS Command Chaining
```
; whoami
| cat /etc/passwd
`id`
$(whoami)
```

## Quick Test Vectors
```
1. Identify framework: Look for .action/.do URLs (Struts2)
2. Check /invoker/JMXInvokerServlet (JBoss deser)
3. Check /jmx-console/ (JBoss misconfiguration)
4. Check management ports: 8080, 9090, 4848
5. Test Struts2: Content-Type manipulation
6. Test command injection: ; whoami | id `id`
7. Check resin-admin, /manager/html (middleware consoles)
```

## High-Value Targets
- **Government systems**: Frequently running outdated Struts2
- **Financial/banking systems**: Legacy Java middleware
- **Telecom infrastructure**: JBoss-based management platforms
- **Enterprise OA systems**: SAP, Oracle middleware
- **CDN/infrastructure nodes**: Internal management consoles

## Root Causes
| Cause | Frequency |
|-------|-----------|
| Unpatched Struts2 framework | Most common |
| Exposed management consoles | Very common |
| Java deserialization in services | Common |
| Direct OS command concatenation | Occasional |
| Unsafe eval/unserialize in PHP | Occasional |
