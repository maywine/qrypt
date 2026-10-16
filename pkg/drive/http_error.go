package drive

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

var sensitiveSnippetPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(\b(?:access_token|refresh_token|refresh_ui|client_secret|sessionKey|token)=)[^&\s"']+`),
	regexp.MustCompile(`(?i)("(?:access_token|refresh_token|refresh_ui|client_secret|sessionKey|token|downloadUrl|fileDownloadUrl|requestURL|cookie|set-cookie|authorization)"\s*:\s*")(?:\\.|[^"\\])+`),
	regexp.MustCompile(`(?i)("(?:cookie|set-cookie|authorization)"\s*:\s*\[)(?:\s*"(?:\\.|[^"\\])*"\s*,?)*`),
	// Cookie headers can contain several credentials separated by spaces or
	// semicolons. Mask the whole header, not only the first cookie.
	regexp.MustCompile(`(?i)(\b(?:cookie|set-cookie|authorization):[ \t]*)[^\r\n]+`),
	// URL userinfo (user:password@) - webdav-style endpoints can embed
	// credentials in the request URL itself.
	regexp.MustCompile(`(://)[^/@\s]+@`),
}

// Snippet returns a short, redacted diagnostic snippet suitable for driver
// error strings and metric payloads.
func Snippet(raw []byte) string {
	raw = bytes.TrimSpace(raw)
	snippet := string(raw)
	for _, pattern := range sensitiveSnippetPatterns {
		snippet = pattern.ReplaceAllString(snippet, "${1}<masked>")
	}
	if len(snippet) > 300 {
		snippet = snippet[:300]
	}
	return snippet
}

// HTTPError builds a driver-prefixed error for an HTTP failure with every
// sensitive field redacted in one place, so drivers do not hand-roll
// status/URL/body splicing:
//
//	<prefix>: METHOD <redacted-URL>: <status> (body: <redacted-snippet>)
//
// The request URL omits query parameters, fragments and embedded credentials;
// response body is truncated to 300 bytes and masked for tokens, cookies,
// download URLs and authorization headers. req and body are optional and
// omitted when nil/empty; a nil resp is allowed for transport failures.
//
// The returned error wraps a stable drive sentinel selected from the status
// code (401 -> ErrAuth, 404 -> ErrNotFound, 429 -> ErrRateLimit,
// 400 -> ErrInvalidInput), so upper layers classify with errors.Is instead
// of parsing text. Never construct driver HTTP errors by hand. Route them
// here so redaction and category rules live in exactly one place.
func HTTPError(prefix string, req *http.Request, resp *http.Response, body []byte) error {
	var b strings.Builder
	b.WriteString(prefix)
	if req != nil && req.URL != nil {
		b.WriteString(": ")
		b.WriteString(req.Method)
		b.WriteString(" ")
		u := *req.URL
		u.User = nil
		u.RawQuery, u.Fragment, u.RawFragment = "", "", ""
		u.ForceQuery = false
		b.WriteString(Snippet([]byte(u.String())))
	}
	if resp != nil {
		b.WriteString(": ")
		b.WriteString(resp.Status)
	}
	if len(body) > 0 {
		b.WriteString(" (body: ")
		b.WriteString(Snippet(body))
		b.WriteString(")")
	}
	err := errors.New(b.String())
	if resp == nil {
		return err
	}
	switch resp.StatusCode {
	case http.StatusUnauthorized:
		return fmt.Errorf("%w: %v", ErrAuth, err)
	case http.StatusNotFound:
		return fmt.Errorf("%w: %v", ErrNotFound, err)
	case http.StatusTooManyRequests:
		return fmt.Errorf("%w: %v", ErrRateLimit, err)
	case http.StatusBadRequest:
		return fmt.Errorf("%w: %v", ErrInvalidInput, err)
	default:
		return err
	}
}
