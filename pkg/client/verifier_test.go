package client

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

type roundTripFunc func(req *http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func newMockHTTPClient(fn roundTripFunc) *http.Client {
	return &http.Client{
		Transport: fn,
	}
}

func TestFetchPublicKeys(t *testing.T) {
	ctx := context.Background()
	sa := "test-sa@project.iam.gserviceaccount.com"

	// 1. Success case with default baseEndpoint ("")
	clientOK := newMockHTTPClient(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewBufferString(`{"key-1": "cert-1", "key-2": "cert-2"}`)),
			Header:     make(http.Header),
		}, nil
	})

	keys, err := FetchPublicKeys(ctx, clientOK, "", sa)
	if err != nil {
		t.Fatalf("unexpected error fetching public keys: %v", err)
	}
	if len(keys) != 2 || keys["key-1"] != "cert-1" {
		t.Fatalf("unexpected keys map: %v", keys)
	}

	// 2. Non-200 response (e.g. 404)
	client404 := newMockHTTPClient(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusNotFound,
			Body:       io.NopCloser(bytes.NewBufferString("Service account not found")),
			Header:     make(http.Header),
		}, nil
	})

	_, err = FetchPublicKeys(ctx, client404, "https://mock.endpoint", sa)
	if err == nil {
		t.Fatalf("expected error on 404 response")
	}

	// 3. Invalid JSON
	clientBadJSON := newMockHTTPClient(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewBufferString(`{invalid json`)),
			Header:     make(http.Header),
		}, nil
	})

	_, err = FetchPublicKeys(ctx, clientBadJSON, "https://mock.endpoint", sa)
	if err == nil {
		t.Fatalf("expected error on bad JSON response")
	}

	// 4. Request creation failure (bad URL character)
	_, err = FetchPublicKeys(ctx, clientOK, "http://invalid \x7f url", sa)
	if err == nil {
		t.Fatalf("expected error for malformed URL")
	}

	// 5. Network / client Do error
	clientErr := newMockHTTPClient(func(req *http.Request) (*http.Response, error) {
		return nil, errors.New("simulated network error")
	})
	_, err = FetchPublicKeys(ctx, clientErr, "https://mock.endpoint", sa)
	if err == nil {
		t.Fatalf("expected error for transport failure")
	}
}

func TestWaitForPublicKeyPublished(t *testing.T) {
	ctx := context.Background()
	sa := "test-sa@project.iam.gserviceaccount.com"

	// 1. Success on retry
	var attempts int32
	clientRetry := newMockHTTPClient(func(req *http.Request) (*http.Response, error) {
		val := atomic.AddInt32(&attempts, 1)
		body := `{"old-key": "cert"}`
		if val >= 2 {
			body = `{"old-key": "cert", "target-key": "target-cert"}`
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewBufferString(body)),
			Header:     make(http.Header),
		}, nil
	})

	err := WaitForPublicKeyPublished(ctx, clientRetry, "https://mock.endpoint", sa, "target-key", 2*time.Second)
	if err != nil {
		t.Fatalf("expected success, got: %v", err)
	}

	// 2. Timeout failure (key never appears)
	clientNever := newMockHTTPClient(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewBufferString(`{"other-key": "cert"}`)),
			Header:     make(http.Header),
		}, nil
	})

	err = WaitForPublicKeyPublished(ctx, clientNever, "https://mock.endpoint", sa, "target-key", 100*time.Millisecond)
	if err == nil {
		t.Fatalf("expected timeout error")
	}

	// 3. Context cancelled early
	cancelCtx, cancel := context.WithCancel(ctx)
	cancel()
	err = WaitForPublicKeyPublished(cancelCtx, clientNever, "https://mock.endpoint", sa, "target-key", 2*time.Second)
	if err == nil {
		t.Fatalf("expected context canceled error")
	}

	// 4. Timeout when FetchPublicKeys consistently errors
	clientErr := newMockHTTPClient(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusInternalServerError,
			Body:       io.NopCloser(bytes.NewBufferString("server error")),
			Header:     make(http.Header),
		}, nil
	})

	err = WaitForPublicKeyPublished(ctx, clientErr, "https://mock.endpoint", sa, "target-key", 100*time.Millisecond)
	if err == nil {
		t.Fatalf("expected error when server consistently fails")
	}
}

func TestWaitForKeyGotten(t *testing.T) {
	ctx := context.Background()
	sa := "test-sa@project.iam.gserviceaccount.com"
	keyID := "test-key"

	mock := NewMockIAMClient()
	mock.AddKey(sa, &KeyInfo{
		ID:       keyID,
		Disabled: false,
	})

	// 1. Success on first try
	err := WaitForKeyGotten(ctx, mock, sa, keyID, 1*time.Second)
	if err != nil {
		t.Fatalf("unexpected error for active key: %v", err)
	}

	// 2. Disabled key error
	mockDisabled := NewMockIAMClient()
	mockDisabled.AddKey(sa, &KeyInfo{
		ID:       keyID,
		Disabled: true,
	})
	err = WaitForKeyGotten(ctx, mockDisabled, sa, keyID, 100*time.Millisecond)
	if err == nil {
		t.Fatalf("expected error for disabled key")
	}

	// 3. Not found / GetKey error timeout
	mockMissing := NewMockIAMClient()
	err = WaitForKeyGotten(ctx, mockMissing, sa, "non-existent", 100*time.Millisecond)
	if err == nil {
		t.Fatalf("expected timeout error for missing key")
	}

	// 4. Context cancelled
	cancelCtx, cancel := context.WithCancel(ctx)
	cancel()
	err = WaitForKeyGotten(cancelCtx, mock, sa, keyID, 1*time.Second)
	if err == nil {
		t.Fatalf("expected error on cancelled context")
	}
}

func TestWaitForKeyFullyPropagated(t *testing.T) {
	ctx := context.Background()
	sa := "test-sa@project.iam.gserviceaccount.com"
	keyID := "key-1"

	// 1. Failure on WaitForKeyGotten
	mockFail := NewMockIAMClient()
	mockFail.GetKeyErr = errors.New("iam failure")
	err := WaitForKeyFullyPropagatedWithClient(ctx, nil, "", mockFail, sa, keyID, 100*time.Millisecond)
	if err == nil {
		t.Fatalf("expected error from WaitForKeyFullyPropagated when IAM fails")
	}

	// 2. Failure on WaitForPublicKeyPublished
	mockOK := NewMockIAMClient()
	mockOK.AddKey(sa, &KeyInfo{ID: keyID, Disabled: false})
	clientMissing := newMockHTTPClient(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewBufferString(`{"different-key": "cert"}`)),
			Header:     make(http.Header),
		}, nil
	})
	err = WaitForKeyFullyPropagatedWithClient(ctx, clientMissing, "https://mock.endpoint", mockOK, sa, keyID, 100*time.Millisecond)
	if err == nil {
		t.Fatalf("expected error from WaitForKeyFullyPropagated when public endpoint fails")
	}

	// 3. Success on both
	clientOK := newMockHTTPClient(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewBufferString(`{"key-1": "cert-1"}`)),
			Header:     make(http.Header),
		}, nil
	})
	err = WaitForKeyFullyPropagatedWithClient(ctx, clientOK, "https://mock.endpoint", mockOK, sa, keyID, 1*time.Second)
	if err != nil {
		t.Fatalf("expected success on both, got: %v", err)
	}

	// 4. Default wrapper test (using mock client that fails WaitForKeyGotten quickly)
	err = WaitForKeyFullyPropagated(ctx, mockFail, sa, keyID, 100*time.Millisecond)
	if err == nil {
		t.Fatalf("expected error from default wrapper")
	}
}

func TestCoverageExtras(t *testing.T) {
	ctx := context.Background()
	sa := "test-sa@project.iam.gserviceaccount.com"

	// Cover httpClient == nil in FetchPublicKeys
	canceledCtx, cancel := context.WithCancel(ctx)
	cancel()
	_, _ = FetchPublicKeys(canceledCtx, nil, "https://mock.endpoint", sa)

	// Cover ctx.Done() during sleep in WaitForPublicKeyPublished
	sleepCtx, cancelSleep := context.WithTimeout(ctx, 25*time.Millisecond)
	defer cancelSleep()
	clientNever := newMockHTTPClient(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewBufferString(`{}`)),
			Header:     make(http.Header),
		}, nil
	})
	_ = WaitForPublicKeyPublished(sleepCtx, clientNever, "https://mock.endpoint", sa, "target-key", 5*time.Second)

	// Cover ctx.Done() during sleep in WaitForKeyGotten
	sleepCtx2, cancelSleep2 := context.WithTimeout(ctx, 25*time.Millisecond)
	defer cancelSleep2()
	mockMissing := NewMockIAMClient()
	_ = WaitForKeyGotten(sleepCtx2, mockMissing, sa, "missing-key", 5*time.Second)
}
