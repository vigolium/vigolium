# File Upload Testing Checklist
> Derived from 30 real-world vulnerability cases (WooYun 2010-2016)

## High-Risk Parameters to Test
| Parameter | Context | Notes |
|-----------|---------|-------|
| `Filedata` | Multipart upload | Standard upload field name |
| `method` | Upload handler dispatch | Method parameter in upload APIs |
| `Connector` | FCKEditor connector | CMS file manager connectors |
| `LMID` / `varnum` / `ids` | Upload form fields | Auxiliary parameters |
| `password` / `c` / `m` | Auth + upload | Combined auth bypass + upload |

## Attack Pattern Distribution
| Pattern | Count | Percentage |
|---------|-------|------------|
| Unrestricted file upload | 6 | 40% |
| Getshell via upload | 3 | 20% |
| Extension bypass | 3 | 20% |
| Weak auth + upload | 1 | 7% |
| Directory traversal + upload | 1 | 7% |

## Common Upload Bypass Techniques

### 1. Client-Side Only Validation (~35% of cases)
The most common flaw: JavaScript-only file type checks with no server-side validation.
- Bypass: Intercept request with proxy, change filename extension
- Bypass: Disable JavaScript and submit directly

### 2. Null Byte Truncation
```
shell.php%00.jpg        (PHP < 5.3.4)
shell.jsp%00.txt        (older Java containers)
shell.asp%00.jpg        (IIS + ASP)
```

### 3. Extension Bypass
```
.php5, .phtml, .pht     (PHP alternatives)
.jspx, .jspa, .jsw      (JSP alternatives)
.asp, .asa, .cer, .cdx   (ASP/IIS alternatives)
.aspx, .ashx, .asmx      (ASP.NET alternatives)
```

### 4. WAF Bypass via Extended ASCII
Append extended ASCII characters after the extension:
```
shell.php[0x7f]         (DEL character)
shell.php[0xcc]         (extended ASCII)
shell.php[0x88]         (extended ASCII)
```
Confirmed to bypass security products on Windows+Apache.

### 5. Content-Type Manipulation
```
Content-Type: image/jpeg    (while uploading .php)
Content-Type: image/gif     (with GIF89a header prepended)
```

### 6. Double Extension / Path Manipulation
```
shell.php.jpg            (Apache misconfiguration)
shell.jpg/.php           (Nginx parsing vulnerability)
../shell.php             (path traversal in filename)
```

## Common Vulnerable Upload Endpoints
```
/upload.jsp
/excelUpload.jsp         (OA systems)
/uploadImageFile_do.jsp  (CMS systems)
/kindeditor/upload_json  (rich text editors)
/fckeditor/editor/filemanager/connectors/
/ueditor/controller      (UEditor)
/regist/expappend_file.jsp
```

## Quick Test Vectors
```
1. Upload .php/.jsp file with valid image Content-Type
2. Upload file.php%00.jpg (null byte truncation)
3. Upload file.phtml / file.php5 (alternative extensions)
4. Upload with ../ in filename (path traversal)
5. Prepend GIF89a to PHP webshell (magic byte bypass)
6. Upload .htaccess to enable PHP execution in upload dir
7. Test double extension: file.php.jpg
```

## Post-Upload Verification
- Determine upload path from response or predictable naming
- Check if uploaded file is directly accessible via HTTP
- Check if file extension is preserved or renamed
- Check if file content is re-processed (image resize strips code)

## High-Value Targets
- **OA/Enterprise systems**: Excel/document upload features
- **CMS admin panels**: Image/file upload in content editors
- **Government procurement systems**: Attachment upload in bid submissions
- **Hospital/edu systems**: Document submission portals
- **Rich text editors**: FCKEditor, KindEditor, UEditor connectors

## Root Causes
| Cause | Frequency |
|-------|-----------|
| Client-side only validation | Most common |
| No server-side extension check | Very common |
| Allowlist not enforced on server | Common |
| Predictable upload paths | Common |
| Upload directory allows execution | Common |
