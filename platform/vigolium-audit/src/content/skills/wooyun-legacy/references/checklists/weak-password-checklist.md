# Weak Password Testing Checklist
> Derived from ~75 real-world vulnerability cases (WooYun 2010-2016)

## High-Risk Parameters to Test
| Parameter | Context |
|-----------|---------|
| `id`, `uid` | User identifiers for enumeration |
| `cmd` | Command execution post-auth |
| `action` | Admin action parameters |
| `dir` | Directory browsing post-auth |
| `systemID` | System selector parameters |
| `APP_UNIT` | Application unit identifiers |
| `site_id` | Multi-tenant site selectors |

## Most Common Default Credentials
| Username | Password | Context |
|----------|----------|---------|
| `admin` | `admin` | Web application admin panels |
| `admin` | `123456` | Chinese web applications |
| `admin` | `admin123` | CMS backends |
| `admin` | `000000` | Enterprise systems |
| `admin` | `password` | Generic default |
| `weblogic` | `weblogic` | Oracle WebLogic console |
| `weblogic` | `12345678` | WebLogic (alternate) |
| `root` | `root` | Database, SSH |
| `test` | `test` | Development accounts |
| `sa` | *(empty)* | MSSQL default |
| `prtgadmin` | `prtgadmin` | PRTG monitoring |
| `tomcat` | `tomcat` | Apache Tomcat manager |

## Common Attack Patterns (by frequency)
1. **Admin panel weak password** (most common)
   - CMS/OA systems with default `admin/123456`
   - No account lockout after failed attempts
2. **Service weak password**
   - WebLogic, JBoss, Tomcat management consoles
   - Database services (MySQL, MSSQL, Oracle)
   - Monitoring platforms (Zabbix, PRTG, Nagios)
3. **Infrastructure weak password**
   - SSH/Telnet with default credentials
   - Router/switch admin interfaces
   - IPMI/BMC management (e.g., Huawei Tecal)
4. **Password → Shell escalation chain**
   - WebLogic console → Deploy WAR → Webshell
   - Tomcat manager → Deploy WAR → Code execution
   - JBoss JMXInvokerServlet → Remote code execution
   - Database access → OS command via xp_cmdshell/UDF

## High-Value Weak Password Targets
| Service | Default Port | Default Creds |
|---------|-------------|---------------|
| WebLogic | 7001 | weblogic/weblogic |
| Tomcat Manager | 8080 | tomcat/tomcat |
| JBoss | 8080 | admin/admin |
| phpMyAdmin | 80/8080 | root/*(empty)* |
| Jenkins | 8080 | *(no auth)* |
| Zabbix | 10051 | Admin/zabbix |
| Nagios | 80 | nagiosadmin/nagios |
| Grafana | 3000 | admin/admin |
| Router | 80 | admin/admin |
| VPN | 443 | *(varies)* |

## Quick Test Vectors
```
# Top password list for Chinese web applications
admin
123456
admin123
000000
password
12345678
test
888888
666666
abc123
admin888
qwerty

# Username enumeration
admin, administrator, root, test, guest
manager, system, sysadmin, operator
[company-name], [domain-prefix]

# Service-specific brute force
hydra -l admin -P passwords.txt TARGET http-post-form
hydra -l root -P passwords.txt TARGET ssh
hydra -l sa -P passwords.txt TARGET mssql
```

## Post-Authentication Escalation
1. **WebLogic** → Deploy WAR package → Webshell
2. **Tomcat** → Manager app → Deploy WAR → Shell
3. **JBoss** → JMXInvokerServlet → Remote execution
4. **phpMyAdmin** → SELECT INTO OUTFILE → Webshell
5. **Database** → Read config files → Internal credentials
6. **OA System** → Internal documents → VPN credentials
7. **Email** → Password reset → Other system access

## Testing Methodology
1. Enumerate admin panel and service login pages
2. Test default credentials for identified services
3. Attempt common username/password combinations
4. Check for account lockout policies
5. Test rate limiting on login endpoints
6. Verify password complexity requirements
7. Check for credential reuse across services
8. Test post-authentication escalation paths

## Common Root Causes
- Default credentials never changed after installation
- No password complexity policy enforcement
- No account lockout or rate limiting
- Management consoles exposed to internet
- Same password reused across multiple services
- Development/test accounts left in production
