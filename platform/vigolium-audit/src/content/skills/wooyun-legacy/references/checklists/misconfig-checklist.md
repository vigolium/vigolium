# Misconfiguration Testing Checklist
> Derived from ~41 real-world vulnerability cases (WooYun 2010-2016)

## High-Risk Parameters to Test
| Parameter | Context |
|-----------|---------|
| `password`, `pwd` | Login forms for default creds |
| `cmd` | Command execution interfaces |
| `comment` | Input fields on exposed panels |
| `service` | Service selectors |
| `ObjName`, `MODE` | Management interface parameters |

## Common Misconfiguration Categories

### 1. Exposed Management Interfaces
| Service | Path/Port | Risk |
|---------|-----------|------|
| WebLogic Console | `:7001/console` | WAR deploy → shell |
| JBoss JMX | `/jmx-console/`, `/invoker/JMXInvokerServlet` | RCE |
| Tomcat Manager | `/manager/html` | WAR deploy → shell |
| phpMyAdmin | `/phpmyadmin/` | Database access |
| Struts2 | `/devmode.action` | RCE via OGNL |
| Spring Actuator | `/actuator/env` | Credential leak |
| Druid Monitor | `/druid/` | SQL query monitor |

### 2. DNS Zone Transfer
```bash
# Test for DNS zone transfer
dig axfr @ns1.target.com target.com
dig axfr @ns2.target.com target.com
# Reveals all DNS records, internal hostnames, IP addresses
```

### 3. Directory Listing
- Web server directory indexing enabled
- Backup directories accessible (`/backup/`, `/bak/`)
- Upload directories browsable (`/upload/`, `/uploads/`)

### 4. Service Exposure (No Authentication)
| Service | Port | Check |
|---------|------|-------|
| MongoDB | 27017 | `mongo TARGET:27017` |
| Redis | 6379 | `redis-cli -h TARGET` |
| Memcached | 11211 | `telnet TARGET 11211` |
| Elasticsearch | 9200 | `curl TARGET:9200` |
| Rsync | 873 | `rsync TARGET::` |
| FTP Anonymous | 21 | `ftp TARGET` (anonymous) |
| Docker API | 2375 | `curl TARGET:2375/info` |

### 5. IIS/Apache Specific
- IIS short filename disclosure (`~1` enumeration)
- IIS write permission enabled (PUT method)
- Apache `.htaccess` bypass
- `crossdomain.xml` / `clientaccesspolicy.xml` overly permissive
- Server-status/server-info pages exposed

## Quick Test Vectors
```
# Management interfaces
/console/
/manager/html
/jmx-console/
/admin/
/phpmyadmin/
/invoker/JMXInvokerServlet

# Configuration files
/web.xml
/web.config
/crossdomain.xml
/robots.txt
/sitemap.xml

# Debug/info endpoints
/phpinfo.php
/info.php
/server-status
/server-info
/.env

# DNS zone transfer
dig axfr @ns1.target.com target.com

# Service scan (common misconfig ports)
nmap -sV -p 21,873,2375,6379,8080,9200,11211,27017 TARGET

# FTP anonymous access
ftp TARGET  # try anonymous / anonymous@

# Rsync enumeration
rsync TARGET::
rsync TARGET::module_name/
```

## Attack Escalation Paths
```
JBoss JMXInvokerServlet → Deploy WAR → Webshell → Internal network
Rsync anonymous → Source code → Database credentials → Data
FTP anonymous → web.config → DB credentials → SQL access
MongoDB no-auth → User data dump → Credential reuse
Redis no-auth → CONFIG SET dir → Write webshell
DNS zone transfer → Internal hostnames → Targeted attacks
```

## Testing Methodology
1. Scan for common management interfaces and default ports
2. Test DNS zone transfer on all nameservers
3. Check for directory listing on web roots and common paths
4. Probe database/cache services for unauthenticated access
5. Test IIS-specific vulnerabilities (short names, write perms)
6. Check cross-domain policy files for overly broad access
7. Verify debug/info endpoints are disabled in production
8. Test FTP and Rsync for anonymous access
9. Check for default installation files and directories

## Common Root Causes
- Management consoles bound to 0.0.0.0 instead of localhost
- Default installations not hardened post-deployment
- DNS servers allowing zone transfers to any requester
- Services deployed without authentication requirements
- Web server directory indexing enabled by default
- Debug features and info pages left in production
- Cross-domain policies set to wildcard (`*`)
- IIS write permissions not properly restricted
