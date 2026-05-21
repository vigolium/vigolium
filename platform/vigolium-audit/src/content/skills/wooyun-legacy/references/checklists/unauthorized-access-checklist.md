# Unauthorized Access Testing Checklist
> Derived from ~55 real-world vulnerability cases (WooYun 2010-2016)

## High-Risk Parameters to Test
| Parameter | Context |
|-----------|---------|
| `uid`, `id` | User/resource identifiers (IDOR) |
| `cmd` | Command/action parameters |
| `lstate` | Login state flags |
| `mod`, `do` | Module/action selectors |
| `ajax` | AJAX request flags (auth bypass) |
| `gsid`, `type` | Session/type identifiers |
| `trueName` | User lookup endpoints |
| `filePath` | File access parameters |
| `code`, `method` | API method selectors |

## Common Attack Patterns (by frequency)
1. **Horizontal privilege escalation (IDOR)** -- Change user ID to access other accounts
2. **Authentication bypass** -- Direct URL access to admin pages
3. **Unauthenticated service access** -- Redis, MongoDB, Memcached exposed without auth
4. **Vertical privilege escalation** -- Regular user accessing admin functions
5. **Cookie/session manipulation** -- Forged or replayed authentication tokens
6. **Sandbox escape** -- Kiosk/terminal breakout via UI interaction

## Unauthenticated Service Exposure
| Service | Default Port | Risk |
|---------|-------------|------|
| Redis | 6379 | Webshell write, key dump |
| MongoDB | 27017 | Full database access |
| Memcached | 11211 | Session data, credential leak |
| Elasticsearch | 9200 | Index data exposure |
| JBOSS JMX | 8080 | Remote code execution |
| Docker API | 2375 | Container escape |
| Zabbix | 10051 | Command execution |
| Hadoop | 50070 | HDFS data access |

## Bypass Techniques
- **Direct URL access**: Skip login page, navigate directly to admin endpoints
- **Cookie manipulation**: Set `isAdmin=1` or modify role in JWT
- **Parameter injection**: Add `&admin=true` or `&role=admin`
- **HTTP method switching**: Try PUT/DELETE when GET/POST is blocked
- **Path traversal to admin**: `/admin/../admin/` or `/./admin/`
- **Request header spoofing**: `X-Forwarded-For: 127.0.0.1` for IP allowlists
- **SQL injection in login**: `' OR 1=1--` in username/password fields
- **Default credentials**: admin/admin, weblogic/weblogic, root/root

## Quick Test Vectors
```
# Direct admin access
/admin/
/manager/
/console/
/system/
/management/

# Service probing
redis-cli -h TARGET -p 6379 INFO
mongo TARGET:27017
curl http://TARGET:9200/_cat/indices

# IDOR testing
GET /api/user/profile?id=1001  (own)
GET /api/user/profile?id=1002  (other)
GET /api/user/profile?id=1     (admin)

# Authentication bypass
# Remove session cookie and access protected endpoints
# Modify user role in cookie/JWT
# Access API endpoints directly without authentication
```

## Testing Methodology
1. Enumerate all endpoints and map authentication requirements
2. Access each endpoint without authentication
3. Test IDOR by modifying user/resource IDs in requests
4. Scan for exposed database/infrastructure services
5. Try default credentials on admin panels and services
6. Test cookie/token manipulation for privilege escalation
7. Check if API endpoints enforce same auth as web UI
8. Verify that role checks are server-side, not client-side

## Common Root Causes
- Missing authentication middleware on admin routes
- Authorization checks in frontend JavaScript only
- Database services bound to 0.0.0.0 without authentication
- Sequential predictable IDs without ownership verification
- Session/role stored in client-modifiable cookie
- Default credentials left unchanged after deployment
- IP-based access control that trusts proxy headers
