Phase: 8
Sequence: 032
Slug: blank-mime-vision-allowlist-bypass
Verdict: FALSE POSITIVE (adversarial)
Rationale: The OpenAI-compat image-URL decoder explicitly skips the jpeg/jpg/png/webp allowlist when the URL starts with data:;base64, ; decoded bytes flow to the mtmd cgo vision pipeline without any MIME sniff or format validation on the Go side, expanding the cgo image-library attack surface to arbitrary attacker-chosen binary content.
Severity-Original: HIGH
PoC-Status: executed
Pre-FP-Flag: none
Debate: archon/chamber-workspace/chamber-02/debate.md
Adversarial-Verdict: DISPROVED
Adversarial-Rationale: The claimed "allowlist" only validates a textual MIME prefix, not decoded bytes — reproduction shows `data:image/jpeg;base64,<arbitrary binary>` and `data:;base64,<arbitrary binary>` both return the identical attacker-controlled byte slice, so the blank-MIME branch does not expand attack surface beyond what is already trivially reachable through a lied `image/jpeg` MIME prefix.
Severity-Final: LOW
PoC-Status: executed

## Summary

`openai/openai.go:674-705 decodeImageURL` validates data-URL inputs against an allowlist of `{"jpeg","jpg","png","webp"}`. An explicit branch at lines 682-684 skips this check when the URL has the literal prefix `data:;base64,` (blank MIME type):

```go
if strings.HasPrefix(url, "data:;base64,") {
    url = strings.TrimPrefix(url, "data:;base64,")
} else {
    valid := false
    for _, t := range types {
        prefix := "data:image/" + t + ";base64,"
        if strings.HasPrefix(url, prefix) { ... }
    }
    if !valid { return nil, errors.New("invalid image input") }
}
```

The remaining pipeline `base64.StdEncoding.DecodeString(url)` -> `api.ImageData` flows into the mtmd (multimodal) cgo pipeline which processes the bytes through libjpeg-turbo/libpng/libwebp without further Go-side MIME sniffing.

## Location

`openai/openai.go:682-684` (blank-MIME skip branch), flowing to `api.ImageData` consumers and `model/vision/mtmd` cgo.

## Attacker Control

Any caller to `/v1/chat/completions` with image messages. Unauthenticated on loopback default.

## Trust Boundary Crossed

Network API -> cgo image libraries.

## Impact

The bypass does not directly produce a concrete exploit in the Go layer but expands the cgo image-library attack surface to ARBITRARY attacker binary content (including non-image formats). libjpeg-turbo, libpng, and libwebp have a consistent history of memory-safety CVEs triggered by malformed input. Any future or currently-unknown CVE in those libraries becomes remotely reachable via `/v1/chat/completions` with no additional requirement beyond the default OpenAI-compat route availability.

The inline comment at the bypass branch ("to match /api/chat's behavior of taking just unadorned base64") shows this is intentional -- but intent is not a security control. The downstream "mtmd does magic-byte validation" argument is defense-in-depth rather than a complete mitigation, because:
- magic-byte sniff happens inside the cgo library; bugs BEFORE the sniff are still triggered.
- mtmd accepts multiple format magic values, so arbitrary-binary input can still match one of them and trigger the corresponding parser.

## Evidence

```
// openai/openai.go:674-705
func decodeImageURL(url string) (api.ImageData, error) {
    if strings.HasPrefix(url, "http://") || strings.HasPrefix(url, "https://") {
        return nil, errors.New("image URLs are not currently supported, ...")
    }

    types := []string{"jpeg", "jpg", "png", "webp"}

    // Support blank mime type to match /api/chat's behavior of taking just unadorned base64
    if strings.HasPrefix(url, "data:;base64,") {
        url = strings.TrimPrefix(url, "data:;base64,")   // <-- bypass
    } else {
        valid := false
        for _, t := range types { ... }
        if !valid { return nil, errors.New("invalid image input") }
    }

    img, err := base64.StdEncoding.DecodeString(url)
    ...
    return img, nil
}
```

## Reproduction Steps

1. `POST /v1/chat/completions` with a message whose content includes:
   ```json
   {"type":"image_url","image_url":{"url":"data:;base64,<base64 of any non-image binary>"}}
   ```
2. Observe that the bytes are forwarded to the vision backend without a 400 response from Go.

Fix direction:
- Remove the blank-MIME special case OR require that even blank-MIME inputs pass a Go-side magic-byte sniff (`net/http.DetectContentType` on the decoded first 512 bytes, reject anything not in the image/* allowlist).
- Document in OpenAPI spec that only `image/{jpeg,png,webp}` MIME is accepted.
