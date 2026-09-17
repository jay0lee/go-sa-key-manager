package client

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

type testRoundTripper struct {
	resp *http.Response
	err  error
}

func (m *testRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if m.err != nil {
		return nil, m.err
	}
	if m.resp != nil {
		m.resp.Request = req
		return m.resp, nil
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Proto:      "HTTP/2.0",
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(`{"status":"ok"}`)),
		Request:    req,
	}, nil
}

func TestHTTPLoggingTransport_Defaults(t *testing.T) {
	tr := NewHTTPLoggingTransport(nil, nil, true)
	if tr.Base != http.DefaultTransport {
		t.Errorf("expected default transport, got %v", tr.Base)
	}
	if tr.Out == nil {
		t.Errorf("expected non-nil default output")
	}
}

func TestHTTPLoggingTransport_RoundTrip_Success(t *testing.T) {
	var buf bytes.Buffer
	mock := &testRoundTripper{
		resp: &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Proto:      "HTTP/1.1",
			Header: http.Header{
				"Content-Type": []string{"application/json"},
				"X-Custom-Res": []string{"res-val"},
			},
			Body: io.NopCloser(strings.NewReader(`{"access_token":"secret-token","privateKeyData":"secret-key"}`)),
		},
	}

	tr := NewHTTPLoggingTransport(mock, &buf, true)

	reqURL, _ := url.Parse("https://iam.googleapis.com/v1/projects?access_token=secret123&other=param")
	req, _ := http.NewRequest(http.MethodPost, reqURL.String(), strings.NewReader(`{"access_token":"secret-req"}`))
	req.Header.Set("Authorization", "Bearer ya29.secret")
	req.Header.Set("Proxy-Authorization", "Basic secretproxy")
	req.Header.Set("X-Goog-Api-Key", "api-key-secret")
	req.Header.Set("X-Request-Id", "req-123")

	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	out := buf.String()

	// Verify request logging
	if !strings.Contains(out, "> POST /v1/projects?access_token=%5BMASKED%5D&other=param HTTP/1.1") {
		t.Errorf("expected masked request line, got:\n%s", out)
	}
	if !strings.Contains(out, "> Host: iam.googleapis.com") {
		t.Errorf("expected Host header, got:\n%s", out)
	}
	if !strings.Contains(out, "> Authorization: Bearer [MASKED]") {
		t.Errorf("expected masked Authorization header, got:\n%s", out)
	}
	if !strings.Contains(out, "> Proxy-Authorization: [MASKED]") {
		t.Errorf("expected masked Proxy-Authorization header, got:\n%s", out)
	}
	if !strings.Contains(out, "> X-Goog-Api-Key: [MASKED]") {
		t.Errorf("expected masked X-Goog-Api-Key header, got:\n%s", out)
	}
	if !strings.Contains(out, "> X-Request-Id: req-123") {
		t.Errorf("expected unmasked X-Request-Id header, got:\n%s", out)
	}
	if !strings.Contains(out, `>   "access_token": "[MASKED]"`) {
		t.Errorf("expected masked JSON request body, got:\n%s", out)
	}

	// Verify response logging
	if !strings.Contains(out, "< HTTP/1.1 200 OK") {
		t.Errorf("expected response line, got:\n%s", out)
	}
	if !strings.Contains(out, "< Content-Type: application/json") {
		t.Errorf("expected Content-Type header, got:\n%s", out)
	}
	if !strings.Contains(out, `<   "access_token": "[MASKED]"`) || !strings.Contains(out, `<   "privateKeyData": "[MASKED]"`) {
		t.Errorf("expected masked JSON response body, got:\n%s", out)
	}
}

func TestHTTPLoggingTransport_RoundTrip_UnmaskedTokens(t *testing.T) {
	var buf bytes.Buffer
	mock := &testRoundTripper{
		resp: &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Header:     http.Header{"Content-Type": []string{"text/plain"}},
			Body:       io.NopCloser(strings.NewReader("plain text response line 1\nline 2")),
		},
	}

	tr := NewHTTPLoggingTransport(mock, &buf, false) // MaskTokens = false

	reqURL, _ := url.Parse("https://example.com/api?access_token=rawsecret")
	req, _ := http.NewRequest(http.MethodGet, reqURL.String(), strings.NewReader("plain request line 1\nline 2"))
	req.Header.Set("Authorization", "Bearer rawtoken")
	req.Header.Set("Proxy-Authorization", "rawproxy")

	_, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "access_token=rawsecret") {
		t.Errorf("expected raw access_token in URL, got:\n%s", out)
	}
	if !strings.Contains(out, "> Authorization: Bearer rawtoken") {
		t.Errorf("expected raw Authorization header, got:\n%s", out)
	}
	if !strings.Contains(out, "> Proxy-Authorization: rawproxy") {
		t.Errorf("expected raw Proxy-Authorization header, got:\n%s", out)
	}
	if !strings.Contains(out, "> plain request line 1") {
		t.Errorf("expected plain text request body, got:\n%s", out)
	}
	if !strings.Contains(out, "< plain text response line 1") {
		t.Errorf("expected plain text response body, got:\n%s", out)
	}
}

func TestHTTPLoggingTransport_RoundTrip_NetworkError(t *testing.T) {
	var buf bytes.Buffer
	netErr := errors.New("connection reset by peer")
	mock := &testRoundTripper{err: netErr}

	tr := NewHTTPLoggingTransport(mock, &buf, true)
	reqURL, _ := url.Parse("https://example.com/test")
	req, _ := http.NewRequest(http.MethodGet, reqURL.String(), nil)

	_, err := tr.RoundTrip(req)
	if !errors.Is(err, netErr) {
		t.Fatalf("expected netErr, got %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "> GET /test HTTP/1.1") {
		t.Errorf("expected request line logged, got:\n%s", out)
	}
	if !strings.Contains(out, "< Request failed: connection reset by peer") {
		t.Errorf("expected request failure logged, got:\n%s", out)
	}
}

func TestHTTPLoggingTransport_EdgeCases(t *testing.T) {
	var buf bytes.Buffer
	mock := &testRoundTripper{
		resp: &http.Response{
			StatusCode: http.StatusNoContent,
			Status:     "204 No Content",
			// No proto, no headers, no body
		},
	}

	tr := &HTTPLoggingTransport{Base: mock, Out: &buf, MaskTokens: true}

	// Request with empty Proto, empty URI, non-bearer auth
	req := &http.Request{
		Method: http.MethodGet,
		URL:    &url.URL{Scheme: "http", Host: "localhost"},
		Header: http.Header{
			"Authorization": []string{"Basic abc"},
		},
	}

	_, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "> GET / HTTP/1.1") {
		t.Errorf("expected default proto and slash uri, got:\n%s", out)
	}
	if !strings.Contains(out, "> Authorization: [MASKED]") {
		t.Errorf("expected non-bearer masked auth, got:\n%s", out)
	}

	// Test maskURL nil
	if u := tr.maskURL(nil); u == nil || u.String() != "" {
		t.Errorf("expected empty url for nil, got %v", u)
	}

	// Test nil Out and empty reqURI
	mockFail := &testRoundTripper{err: errors.New("expected fail")}
	trNilOut := &HTTPLoggingTransport{Base: mockFail} // Out is nil -> falls back to os.Stderr
	reqOpaque := &http.Request{
		Method: http.MethodGet,
		URL:    &url.URL{Opaque: "opaque-target"},
	}
	_, _ = trNilOut.RoundTrip(reqOpaque)

	// Test nil Base
	trNilBase := &HTTPLoggingTransport{Out: &buf} // Base is nil -> falls back to http.DefaultTransport
	reqBadURL := &http.Request{
		Method: http.MethodGet,
		URL:    &url.URL{Scheme: "http", Host: "127.0.0.1:0"},
	}
	_, _ = trNilBase.RoundTrip(reqBadURL)
}
