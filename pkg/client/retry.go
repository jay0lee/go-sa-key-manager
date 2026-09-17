package client

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/googleapis/gax-go/v2"
	"google.golang.org/api/googleapi"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// IsRetryableGCPError determines whether an error from Google Cloud APIs represents
// a transient failure that should be retried with exponential backoff.
//
// Retryable conditions per Google AIP-4221:
// - ResourceExhausted (rate limiting / quota exhaustion / HTTP 429)
// - Unavailable (transient backend unavailability / network loss / HTTP 503)
// - DeadlineExceeded (operation timed out on server / HTTP 504)
// - Aborted (transient concurrency conflict / HTTP 409)
//
// Non-retryable conditions:
// - FailedPrecondition (organization policy violation)
// - PermissionDenied (IAM authorization failure)
// - NotFound (resource does not exist)
// - InvalidArgument (client request malformed)
// - AlreadyExists (key or resource collision)
func IsRetryableGCPError(err error) bool {
	if err == nil {
		return false
	}
	var gErr *googleapi.Error
	if errors.As(err, &gErr) {
		return IsRetryableHTTPStatus(gErr.Code)
	}
	s, ok := status.FromError(err)
	if ok {
		switch s.Code() {
		case codes.ResourceExhausted,
			codes.Unavailable,
			codes.DeadlineExceeded,
			codes.Aborted:
			return true
		default:
			return false
		}
	}
	return false
}

// IsRetryableHTTPStatus returns true if an HTTP status code indicates a transient failure.
func IsRetryableHTTPStatus(statusCode int) bool {
	switch statusCode {
	case http.StatusTooManyRequests, // 429
		http.StatusServiceUnavailable, // 503
		http.StatusGatewayTimeout,     // 504
		http.StatusBadGateway:         // 502
		return true
	default:
		return false
	}
}

// ExtractRetryDelay inspects an error's status details or HTTP headers for retry delay information.
// If Google Cloud specified a recommended retry delay (e.g. "retry in 1m0s" or Retry-After header), it returns that duration.
func ExtractRetryDelay(err error) (time.Duration, bool) {
	if err == nil {
		return 0, false
	}
	var gErr *googleapi.Error
	if errors.As(err, &gErr) && gErr.Header != nil {
		if retryAfter := gErr.Header.Get("Retry-After"); retryAfter != "" {
			if seconds, parseErr := strconv.Atoi(retryAfter); parseErr == nil && seconds > 0 {
				return time.Duration(seconds) * time.Second, true
			}
		}
	}
	s, ok := status.FromError(err)
	if !ok {
		return 0, false
	}
	for _, detail := range s.Details() {
		if retryInfo, ok := detail.(*errdetails.RetryInfo); ok {
			if retryInfo.RetryDelay != nil {
				return retryInfo.RetryDelay.AsDuration(), true
			}
		}
	}
	return 0, false
}

// StandardGCPRetryer implements gax.Retryer using truncated exponential backoff with full jitter,
// and respects server-provided RetryInfo when present.
type StandardGCPRetryer struct {
	bo gax.Backoff
}

// NewStandardGCPRetryer returns a new gax.Retryer configured according to Google AIP-4221.
func NewStandardGCPRetryer() gax.Retryer {
	return &StandardGCPRetryer{
		bo: gax.Backoff{
			Initial:    1 * time.Second,
			Max:        30 * time.Second,
			Multiplier: 2.0,
		},
	}
}

// Retry implements gax.Retryer.
func (r *StandardGCPRetryer) Retry(err error) (time.Duration, bool) {
	if !IsRetryableGCPError(err) {
		return 0, false
	}
	if serverDelay, ok := ExtractRetryDelay(err); ok && serverDelay > 0 {
		return serverDelay, true
	}
	return r.bo.Pause(), true
}

// StandardCallOptions returns gax.CallOptions with standard GCP exponential backoff and retry enabled.
func StandardCallOptions() []gax.CallOption {
	return []gax.CallOption{
		gax.WithRetry(NewStandardGCPRetryer),
	}
}

// BackoffConfig configures the behavior of RetryWithBackoff.
type BackoffConfig struct {
	InitialDelay time.Duration
	MaxDelay     time.Duration
	Multiplier   float64
	MaxAttempts  int
	OnRetry      func(attempt int, pause time.Duration, err error)
}

// DefaultBackoffConfig returns standard AIP-4221 retry settings.
func DefaultBackoffConfig() BackoffConfig {
	return BackoffConfig{
		InitialDelay: 1 * time.Second,
		MaxDelay:     60 * time.Second,
		Multiplier:   2.0,
		MaxAttempts:  5,
	}
}

// RetryWithBackoff executes an operation, retrying on transient GCP errors using exponential backoff with jitter.
// If the server provides RetryInfo (e.g. rate limit retry duration), that delay is honored.
func RetryWithBackoff(ctx context.Context, cfg BackoffConfig, op func() error) error {
	if cfg.InitialDelay <= 0 {
		cfg.InitialDelay = 1 * time.Second
	}
	if cfg.MaxDelay <= 0 {
		cfg.MaxDelay = 60 * time.Second
	}
	if cfg.Multiplier < 1.0 {
		cfg.Multiplier = 2.0
	}
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = 5
	}

	bo := gax.Backoff{
		Initial:    cfg.InitialDelay,
		Max:        cfg.MaxDelay,
		Multiplier: cfg.Multiplier,
	}

	var lastErr error
	for attempt := 1; attempt <= cfg.MaxAttempts; attempt++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		lastErr = op()
		if lastErr == nil {
			return nil
		}
		if !IsRetryableGCPError(lastErr) {
			return lastErr
		}
		if attempt == cfg.MaxAttempts {
			break
		}

		var pause time.Duration
		if serverDelay, ok := ExtractRetryDelay(lastErr); ok && serverDelay > 0 {
			pause = serverDelay
		} else {
			pause = bo.Pause()
		}

		if cfg.OnRetry != nil {
			cfg.OnRetry(attempt, pause, lastErr)
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(pause):
		}
	}
	return lastErr
}
