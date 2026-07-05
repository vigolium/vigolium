// Helpers for reproducing a scanned request as a runnable curl command.
//
// curl rewrites the request target in two ways that silently break fuzz/bypass
// paths: it performs RFC 3986 dot-segment removal (squashing "/../" and "/./")
// on the path unless --path-as-is is set, and it treats an unencoded "#" as the
// start of a fragment, which is never sent on the wire. Bypass targets such as
// "/#/../demo.log" or "/%23/../admin" rely on both surviving verbatim.

// Whether the request target needs curl's --path-as-is flag to reach the wire
// unmodified: true when it carries a literal "#" (which, once encoded to %23,
// leaves a "/../" curl would otherwise squash) or a literal dot-segment.
export function curlNeedsPathAsIs(target: string): boolean {
  if (target.includes("#")) return true;
  const path = target.split("?")[0];
  return /(^|\/)\.{1,2}(\/|$)/.test(path);
}

// Encode a "#" as %23 so curl keeps it in the path instead of treating the rest
// of the target as an (unsent) fragment. Everything else is already on-the-wire
// escaped, so it is passed through untouched.
export function curlEncodeTarget(target: string): string {
  return target.replace(/#/g, "%23");
}
