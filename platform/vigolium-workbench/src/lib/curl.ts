// Convert a raw HTTP request string into an equivalent `curl` command.
//
// The raw request looks like:
//   GET /path?q=1 HTTP/1.1
//   Host: example.com
//   User-Agent: ...
//
//   <optional body>
//
// `matchedAt` (a finding's matched URLs) is used only to recover the scheme
// (http vs https), which the raw request line never carries; defaults to https.

function shellQuote(value: string): string {
  // Wrap in single quotes, escaping any embedded single quotes the POSIX way.
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

// curl rewrites the request target in two ways that break fuzz/bypass paths: it
// squashes RFC 3986 dot-segments ("/../", "/./") on the path unless --path-as-is
// is set, and it treats an unencoded "#" as a fragment (never sent). Bypass
// targets like "/#/../demo.log" or "/%23/../admin" rely on both surviving.

// True when the target needs --path-as-is to reach the wire unmodified: a literal
// "#" (which, once encoded to %23, leaves a "/../" curl would squash) or a
// literal dot-segment in the path.
function needsPathAsIs(target: string): boolean {
  if (target.includes('#')) return true;
  const path = target.split('?')[0];
  return /(^|\/)\.{1,2}(\/|$)/.test(path);
}

// Encode "#" as %23 so curl keeps it in the path instead of dropping the rest of
// the target as a fragment. Everything else is already on-the-wire escaped.
function encodeTarget(target: string): string {
  return target.replace(/#/g, '%23');
}

export function rawRequestToCurl(rawRequest: string, matchedAt?: string[]): string {
  const normalized = rawRequest.replace(/\r\n/g, '\n');
  // Split head (request line + headers) from body at the first blank line.
  const sep = normalized.indexOf('\n\n');
  const head = sep === -1 ? normalized : normalized.slice(0, sep);
  const body = sep === -1 ? '' : normalized.slice(sep + 2);

  const lines = head.split('\n');
  const requestLine = (lines.shift() ?? '').trim();
  const [method = 'GET', target = '/'] = requestLine.split(/\s+/);

  const headers: Array<[string, string]> = [];
  let host = '';
  for (const line of lines) {
    const idx = line.indexOf(':');
    if (idx === -1) continue;
    const name = line.slice(0, idx).trim();
    const val = line.slice(idx + 1).trim();
    if (!name) continue;
    if (name.toLowerCase() === 'host') host = val;
    headers.push([name, val]);
  }

  // Build the absolute URL. If the request target is already absolute
  // (proxy-style), use it as-is; otherwise join scheme + host + target. "#" is
  // encoded so curl keeps the bypass segment in the path.
  let url: string;
  if (/^https?:\/\//i.test(target)) {
    url = encodeTarget(target);
  } else {
    let scheme = 'https';
    const matched = matchedAt?.find((u) => /^https?:\/\//i.test(u));
    if (matched) {
      scheme = matched.toLowerCase().startsWith('http://') ? 'http' : 'https';
    } else if (!host) {
      scheme = 'http';
    }
    url = `${scheme}://${host}${encodeTarget(target)}`;
  }

  // Bypass/fuzz targets (dot-segments or a literal "#") need --path-as-is so curl
  // replays them without collapsing "/../" or "/./".
  const flags = needsPathAsIs(target) ? '-i -s -k --path-as-is' : '-i -s -k';
  const parts: string[] = [`curl ${flags} -X ${method} ${shellQuote(url)}`];
  for (const [name, val] of headers) {
    parts.push(`  -H ${shellQuote(`${name}: ${val}`)}`);
  }
  if (body.trim() !== '') {
    parts.push(`  --data-raw ${shellQuote(body)}`);
  }

  return parts.join(' \\\n');
}
