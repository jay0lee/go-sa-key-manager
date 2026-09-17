package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
)

var (
	jsonTokenRegex      = regexp.MustCompile(`("access_token"\s*:\s*)"([^"]+)"`)
	jsonPrivateKeyRegex = regexp.MustCompile(`("privateKeyData"\s*:\s*)"([^"]+)"`)
)

// HTTPLoggingTransport wraps an http.RoundTripper to print full HTTP request
// and response wire conversations to an io.Writer with token masking support.
type HTTPLoggingTransport struct {
	Base       http.RoundTripper
	Out        io.Writer
	MaskTokens bool
}

// NewHTTPLoggingTransport creates a new HTTPLoggingTransport.
func NewHTTPLoggingTransport(base http.RoundTripper, out io.Writer, maskTokens bool) *HTTPLoggingTransport {
	if base == nil {
		base = http.DefaultTransport
	}
	if out == nil {
		out = os.Stderr
	}
	return &HTTPLoggingTransport{
		Base:       base,
		Out:        out,
		MaskTokens: maskTokens,
	}
}

// RoundTrip executes a single HTTP transaction and logs the request and response.
func (t *HTTPLoggingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	out := t.Out
	if out == nil {
		out = os.Stderr
	}

	// 1. Log Request
	proto := req.Proto
	if proto == "" {
		proto = "HTTP/1.1"
	}

	reqURL := t.maskURL(req.URL)
	reqURI := reqURL.RequestURI()

	fmt.Fprintf(out, "> %s %s %s\n", req.Method, reqURI, proto)
	fmt.Fprintf(out, "> Host: %s\n", req.URL.Host)

	// Sort header keys for deterministic output
	reqHeaderKeys := make([]string, 0, len(req.Header))
	for k := range req.Header {
		if !strings.EqualFold(k, "Host") {
			reqHeaderKeys = append(reqHeaderKeys, k)
		}
	}
	sort.Strings(reqHeaderKeys)

	for _, k := range reqHeaderKeys {
		for _, v := range req.Header[k] {
			val := t.maskHeaderValue(k, v)
			fmt.Fprintf(out, "> %s: %s\n", k, val)
		}
	}

	if req.Body != nil {
		reqBytes, err := io.ReadAll(req.Body)
		if err == nil {
			req.Body = io.NopCloser(bytes.NewReader(reqBytes))
			if len(reqBytes) > 0 {
				fmt.Fprintln(out, ">")
				t.printBody(out, ">", reqBytes)
			}
		}
	}

	// 2. Execute Request
	base := t.Base
	if base == nil {
		base = http.DefaultTransport
	}
	resp, err := base.RoundTrip(req)
	if err != nil {
		fmt.Fprintf(out, "< Request failed: %v\n", err)
		return nil, err
	}

	// 3. Log Response
	respProto := resp.Proto
	if respProto == "" {
		respProto = "HTTP/1.1"
	}
	fmt.Fprintf(out, "< %s %s\n", respProto, resp.Status)

	respHeaderKeys := make([]string, 0, len(resp.Header))
	for k := range resp.Header {
		respHeaderKeys = append(respHeaderKeys, k)
	}
	sort.Strings(respHeaderKeys)

	for _, k := range respHeaderKeys {
		for _, v := range resp.Header[k] {
			val := t.maskHeaderValue(k, v)
			fmt.Fprintf(out, "< %s: %s\n", k, val)
		}
	}

	if resp.Body != nil {
		respBytes, err := io.ReadAll(resp.Body)
		if err == nil {
			resp.Body = io.NopCloser(bytes.NewReader(respBytes))
			if len(respBytes) > 0 {
				fmt.Fprintln(out, "<")
				t.printBody(out, "<", respBytes)
			}
		}
	}

	return resp, nil
}

func (t *HTTPLoggingTransport) maskHeaderValue(name, val string) string {
	if !t.MaskTokens {
		return val
	}
	lower := strings.ToLower(name)
	switch lower {
	case "authorization":
		if strings.HasPrefix(strings.ToLower(val), "bearer ") {
			return "Bearer [MASKED]"
		}
		return "[MASKED]"
	case "proxy-authorization", "x-goog-api-key":
		return "[MASKED]"
	default:
		return val
	}
}

func (t *HTTPLoggingTransport) maskURL(u *url.URL) *url.URL {
	if u == nil {
		return &url.URL{}
	}
	if !t.MaskTokens {
		return u
	}

	q := u.Query()
	modified := false
	for _, param := range []string{"access_token", "key", "token"} {
		if q.Has(param) {
			q.Set(param, "[MASKED]")
			modified = true
		}
	}

	if !modified {
		return u
	}

	copyURL := *u
	copyURL.RawQuery = q.Encode()
	return &copyURL
}

func (t *HTTPLoggingTransport) printBody(out io.Writer, prefix string, body []byte) {
	processed := body
	if t.MaskTokens {
		processed = jsonTokenRegex.ReplaceAll(processed, []byte(`$1"[MASKED]"`))
		processed = jsonPrivateKeyRegex.ReplaceAll(processed, []byte(`$1"[MASKED]"`))
	}

	var pretty bytes.Buffer
	if json.Indent(&pretty, processed, "", "  ") == nil {
		lines := strings.Split(pretty.String(), "\n")
		for _, line := range lines {
			fmt.Fprintf(out, "%s %s\n", prefix, line)
		}
		return
	}

	lines := strings.Split(string(processed), "\n")
	for _, line := range lines {
		fmt.Fprintf(out, "%s %s\n", prefix, line)
	}
}
