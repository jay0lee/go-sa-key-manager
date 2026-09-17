package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DefaultPublicMetadataEndpoint is the base URL for Google's public, unauthenticated
// X.509 certificate metadata endpoint for service accounts.
const DefaultPublicMetadataEndpoint = "https://www.googleapis.com/service_accounts/v1/metadata/x509"

// FetchPublicKeys retrieves the map of active key IDs to public certificates
// from Google's unauthenticated metadata endpoint.
func FetchPublicKeys(ctx context.Context, httpClient *http.Client, baseEndpoint, saEmail string) (map[string]string, error) {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	if baseEndpoint == "" {
		baseEndpoint = DefaultPublicMetadataEndpoint
	}

	reqURL := fmt.Sprintf("%s/%s?_cb=%d", strings.TrimSuffix(baseEndpoint, "/"), url.PathEscape(saEmail), time.Now().UnixNano())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create public key request: %w", err)
	}

	req.Header.Set("Cache-Control", "no-cache, no-store")
	req.Header.Set("Pragma", "no-cache")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("public key request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("public key endpoint returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var certs map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&certs); err != nil {
		return nil, fmt.Errorf("failed to parse public keys JSON: %w", err)
	}

	return certs, nil
}

// WaitForPublicKeyPublished polls Google's unauthenticated metadata endpoint until
// the specified key ID appears in the returned certificate map.
func WaitForPublicKeyPublished(ctx context.Context, httpClient *http.Client, baseEndpoint, saEmail, keyID string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	interval := 50 * time.Millisecond
	var lastErr error

	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		certs, err := FetchPublicKeys(ctx, httpClient, baseEndpoint, saEmail)
		if err == nil {
			if _, ok := certs[keyID]; ok {
				return nil
			}
			lastErr = fmt.Errorf("key %s not yet published in public certificate map", keyID)
		} else {
			lastErr = err
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(interval):
			if interval < 500*time.Millisecond {
				interval *= 2
			}
		}
	}

	return fmt.Errorf("timed out waiting for key %s to appear on public metadata endpoint: %w", keyID, lastErr)
}

// WaitForKeyGotten polls the IAM Admin API until GetKey returns the active key.
func WaitForKeyGotten(ctx context.Context, iamClient IAMClient, saEmail, keyID string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	interval := 50 * time.Millisecond
	var lastErr error

	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		key, err := iamClient.GetKey(ctx, saEmail, keyID)
		if err == nil && key != nil {
			if !key.Disabled {
				return nil
			}
			lastErr = fmt.Errorf("key %s is disabled", keyID)
		} else {
			lastErr = err
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(interval):
			if interval < 500*time.Millisecond {
				interval *= 2
			}
		}
	}

	return fmt.Errorf("timed out waiting for key %s to be gotten via IAM: %w", keyID, lastErr)
}

// WaitForKeyFullyPropagatedWithClient ensures a key is both queryable via IAM (gotten)
// and visible on Google's public unauthenticated metadata endpoint using custom HTTP settings.
func WaitForKeyFullyPropagatedWithClient(ctx context.Context, httpClient *http.Client, baseEndpoint string, iamClient IAMClient, saEmail, keyID string, timeout time.Duration) error {
	// First barrier: IAM Admin API GetKey
	if err := WaitForKeyGotten(ctx, iamClient, saEmail, keyID, timeout); err != nil {
		return err
	}

	// Second barrier: Public unauthenticated metadata endpoint
	return WaitForPublicKeyPublished(ctx, httpClient, baseEndpoint, saEmail, keyID, timeout)
}

// WaitForKeyFullyPropagated ensures a key is both queryable via IAM (gotten)
// and visible on Google's public unauthenticated metadata endpoint.
func WaitForKeyFullyPropagated(ctx context.Context, iamClient IAMClient, saEmail, keyID string, timeout time.Duration) error {
	return WaitForKeyFullyPropagatedWithClient(ctx, nil, "", iamClient, saEmail, keyID, timeout)
}
