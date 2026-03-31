# Information Disclosure Testing Checklist
> Derived from ~56 real-world vulnerability cases (WooYun 2010-2016)

## High-Risk Parameters to Test
| Parameter | Context |
|-----------|---------|
| `id`, `uid` | Sequential resource identifiers |
| `order_id`, `orderId` | Order enumeration |
| `callback` | JSONP endpoints leaking user data |
| `method` | API method selectors |
| `p`, `page` | Pagination revealing total counts |
| `inputFile` | File read endpoints |
| `query`, `q` | Search endpoints reflecting data |

## Common Attack Patterns (by frequency)
1. **Source code/config exposure** (most common)
   - `.svn/entries` or `.svn/wc.db` accessible
   - `.git/config` or `.git/HEAD` accessible
   - Backup files: `*.bak`, `*.sql`, `*.tar.gz`, `website.rar`
   - `web.config`, `database.php`, `.env` exposed
2. **Log file exposure**
   - Application logs containing sessions, credentials
   - Debug endpoints left enabled in production
3. **API data over-exposure**
   - JSONP endpoints returning user data cross-origin
   - API responses including more fields than UI displays
   - Sequential ID enumeration on order/user endpoints
4. **Database credential leak**
   - Config files with plaintext DB credentials
   - Error messages revealing connection strings
   - GitHub/code repository credential exposure
5. **Session/credential leak**
   - Session tokens in log files
   - Credentials in URL parameters (GET requests)
   - Default management passwords in documentation

## Source Control Exposure
| Path | Tool | Risk |
|------|------|------|
| `.svn/entries` | SVN | Source code + history |
| `.svn/wc.db` | SVN 1.7+ | SQLite with full paths |
| `.git/config` | Git | Remote URLs, credentials |
| `.git/HEAD` | Git | Branch info, clone source |
| `.DS_Store` | macOS | Directory listing |
| `.idea/` | JetBrains | Project config, DB creds |
| `WEB-INF/web.xml` | Java | Servlet mappings, config |

## Quick Test Vectors
```
# Source control files
/.svn/entries
/.svn/wc.db
/.git/config
/.git/HEAD
/.DS_Store

# Backup files
/backup.sql
/backup.tar.gz
/website.rar
/db.sql
/dump.sql
/*.bak

# Configuration files
/web.config
/wp-config.php
/config/database.yml
/application.properties
/.env
/phpinfo.php

# Log files
/logs/
/log/
/debug.log
/error.log
/seeyon/logs/ctp.log

# JSONP data leak
/api/userinfo?callback=test

# GitHub search for credentials
site:github.com "company.com" password
site:github.com "company.com" smtp
```

## Testing Methodology
1. Enumerate common sensitive file paths (source control, backups, configs)
2. Check for directory listing on all discovered directories
3. Search GitHub/GitLab for organization credential leaks
4. Test JSONP endpoints for cross-origin data exposure
5. Check error pages for stack traces and config details
6. Probe log file locations for session/credential leakage
7. Test sequential ID enumeration on data endpoints
8. Check API responses for excessive data exposure
9. Scan for debug/admin endpoints left in production

## Information Escalation Chain
```
Source code leak → Database credentials → Full database access
GitHub credential leak → Email access → VPN/internal access
Log file exposure → Session tokens → Account takeover
JSONP endpoint → User data → Credential stuffing
```

## Common Root Causes
- Development files (.svn, .git) deployed to production
- Backup files stored in web-accessible directories
- Debug/logging features enabled in production
- JSONP endpoints without access control
- Error messages revealing internal details
- Credentials committed to public code repositories
- Default management interfaces left accessible
