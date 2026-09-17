package client

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"
)

func TestIsRetryableGCPError(t *testing.T) {
	if IsRetryableGCPError(nil) {
		t.Errorf("expected nil error to not be retryable")
	}

	if IsRetryableGCPError(errors.New("plain non-grpc error")) {
		t.Errorf("expected plain error to not be retryable")
	}

	retryableCodes := []codes.Code{
		codes.ResourceExhausted,
		codes.Unavailable,
		codes.DeadlineExceeded,
		codes.Aborted,
	}
	for _, code := range retryableCodes {
		err := status.Error(code, "transient error")
		if !IsRetryableGCPError(err) {
			t.Errorf("expected code %v to be retryable", code)
		}
	}

	nonRetryableCodes := []codes.Code{
		codes.OK,
		codes.Canceled,
		codes.Unknown,
		codes.InvalidArgument,
		codes.NotFound,
		codes.AlreadyExists,
		codes.PermissionDenied,
		codes.FailedPrecondition,
		codes.OutOfRange,
		codes.Unimplemented,
		codes.Internal,
		codes.DataLoss,
		codes.Unauthenticated,
	}
	for _, code := range nonRetryableCodes {
		err := status.Error(code, "non-retryable error")
		if IsRetryableGCPError(err) {
			t.Errorf("expected code %v to NOT be retryable", code)
		}
	}

	notFoundErr1 := status.Error(codes.NotFound, "Service account projects/-/serviceAccounts/my-sa@proj.iam.gserviceaccount.com does not exist.")
	if IsRetryableGCPError(notFoundErr1) {
		t.Errorf("expected NotFound to NOT be retryable")
	}

	notFoundErr2 := status.Error(codes.NotFound, "serviceaccounts/my-sa does not exist")
	if IsRetryableGCPError(notFoundErr2) {
		t.Errorf("expected NotFound to NOT be retryable")
	}

	notFoundErr3 := status.Error(codes.NotFound, "Key projects/-/serviceAccounts/my-sa/keys/k1 does not exist.")
	if IsRetryableGCPError(notFoundErr3) {
		t.Errorf("expected key NotFound to NOT be retryable")
	}
}

func TestIsRetryableHTTPStatus(t *testing.T) {
	retryable := []int{
		http.StatusTooManyRequests,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout,
		http.StatusBadGateway,
	}
	for _, sc := range retryable {
		if !IsRetryableHTTPStatus(sc) {
			t.Errorf("expected HTTP %d to be retryable", sc)
		}
	}

	nonRetryable := []int{
		http.StatusOK,
		http.StatusCreated,
		http.StatusBadRequest,
		http.StatusUnauthorized,
		http.StatusForbidden,
		http.StatusNotFound,
		http.StatusInternalServerError,
	}
	for _, sc := range nonRetryable {
		if IsRetryableHTTPStatus(sc) {
			t.Errorf("expected HTTP %d to NOT be retryable", sc)
		}
	}
}

func TestExtractRetryDelay(t *testing.T) {
	// 1. Nil error
	if _, ok := ExtractRetryDelay(nil); ok {
		t.Errorf("expected nil error to have no delay")
	}

	// 2. Plain error
	if _, ok := ExtractRetryDelay(errors.New("plain error")); ok {
		t.Errorf("expected plain error to have no delay")
	}

	// 3. gRPC error without details
	if _, ok := ExtractRetryDelay(status.Error(codes.ResourceExhausted, "quota")); ok {
		t.Errorf("expected error without details to have no delay")
	}

	// 4. gRPC error with details other than RetryInfo
	st := status.New(codes.ResourceExhausted, "quota")
	stWithOther, _ := st.WithDetails(&errdetails.QuotaFailure{})
	if _, ok := ExtractRetryDelay(stWithOther.Err()); ok {
		t.Errorf("expected QuotaFailure detail to have no delay")
	}

	// 5. gRPC error with RetryInfo but nil RetryDelay
	stWithNilDelay, _ := st.WithDetails(&errdetails.RetryInfo{RetryDelay: nil})
	if _, ok := ExtractRetryDelay(stWithNilDelay.Err()); ok {
		t.Errorf("expected RetryInfo with nil delay to return false")
	}

	// 6. gRPC error with valid RetryInfo
	wantDelay := 15 * time.Second
	stWithValid, _ := st.WithDetails(&errdetails.RetryInfo{
		RetryDelay: durationpb.New(wantDelay),
	})
	delay, ok := ExtractRetryDelay(stWithValid.Err())
	if !ok || delay != wantDelay {
		t.Errorf("expected delay %v, got %v (ok=%v)", wantDelay, delay, ok)
	}
}

func TestStandardGCPRetryer(t *testing.T) {
	retryer := NewStandardGCPRetryer()

	// Non-retryable error
	pause, shouldRetry := retryer.Retry(status.Error(codes.PermissionDenied, "denied"))
	if shouldRetry || pause != 0 {
		t.Errorf("expected non-retryable error to return (0, false), got (%v, %v)", pause, shouldRetry)
	}

	// Retryable error without RetryInfo
	pause, shouldRetry = retryer.Retry(status.Error(codes.Unavailable, "unavailable"))
	if !shouldRetry || pause <= 0 {
		t.Errorf("expected retryable error to return true and positive pause, got (%v, %v)", pause, shouldRetry)
	}

	// Retryable error with RetryInfo
	wantDelay := 5 * time.Second
	st := status.New(codes.ResourceExhausted, "rate limit")
	stWithDelay, _ := st.WithDetails(&errdetails.RetryInfo{RetryDelay: durationpb.New(wantDelay)})
	pause, shouldRetry = retryer.Retry(stWithDelay.Err())
	if !shouldRetry || pause != wantDelay {
		t.Errorf("expected server delay %v, got (%v, %v)", wantDelay, pause, shouldRetry)
	}

	// StandardCallOptions produces non-empty slice
	opts := StandardCallOptions()
	if len(opts) != 1 {
		t.Errorf("expected 1 call option, got %d", len(opts))
	}
}

func TestRetryWithBackoff(t *testing.T) {
	ctx := context.Background()

	// 1. Success on first attempt with default config
	called := 0
	err := RetryWithBackoff(ctx, DefaultBackoffConfig(), func() error {
		called++
		return nil
	})
	if err != nil || called != 1 {
		t.Errorf("expected success on first attempt, got err=%v, called=%d", err, called)
	}

	// 2. Default zero config normalization
	called = 0
	err = RetryWithBackoff(ctx, BackoffConfig{}, func() error {
		called++
		return nil
	})
	if err != nil || called != 1 {
		t.Errorf("expected zero-config normalization to succeed, got err=%v, called=%d", err, called)
	}

	// 3. Fail immediately on non-retryable error
	called = 0
	nonRetryErr := status.Error(codes.PermissionDenied, "forbidden")
	err = RetryWithBackoff(ctx, DefaultBackoffConfig(), func() error {
		called++
		return nonRetryErr
	})
	if !errors.Is(err, nonRetryErr) || called != 1 {
		t.Errorf("expected non-retryable error to fail immediately, got err=%v, called=%d", err, called)
	}

	// 4. Success after retries with OnRetry callback
	called = 0
	retriesLogged := 0
	cfg := BackoffConfig{
		InitialDelay: 1 * time.Millisecond,
		MaxDelay:     10 * time.Millisecond,
		Multiplier:   2.0,
		MaxAttempts:  3,
		OnRetry: func(attempt int, pause time.Duration, err error) {
			retriesLogged++
		},
	}
	err = RetryWithBackoff(ctx, cfg, func() error {
		called++
		if called < 2 {
			return status.Error(codes.Unavailable, "transient error")
		}
		return nil
	})
	if err != nil || called != 2 || retriesLogged != 1 {
		t.Errorf("expected success on 2nd attempt, got err=%v, called=%d, retriesLogged=%d", err, called, retriesLogged)
	}

	// 5. Exhaust max attempts
	called = 0
	transientErr := status.Error(codes.Unavailable, "service unavailable")
	cfg = BackoffConfig{
		InitialDelay: 1 * time.Millisecond,
		MaxDelay:     5 * time.Millisecond,
		Multiplier:   1.5,
		MaxAttempts:  3,
	}
	err = RetryWithBackoff(ctx, cfg, func() error {
		called++
		return transientErr
	})
	if !errors.Is(err, transientErr) || called != 3 {
		t.Errorf("expected exhaustion of 3 attempts, got err=%v, called=%d", err, called)
	}

	// 6. Server-specified RetryDelay in RetryWithBackoff
	called = 0
	st := status.New(codes.ResourceExhausted, "rate limit")
	stWithDelay, _ := st.WithDetails(&errdetails.RetryInfo{RetryDelay: durationpb.New(2 * time.Millisecond)})
	cfg = BackoffConfig{
		InitialDelay: 100 * time.Millisecond,
		MaxDelay:     500 * time.Millisecond,
		Multiplier:   2.0,
		MaxAttempts:  2,
	}
	err = RetryWithBackoff(ctx, cfg, func() error {
		called++
		if called == 1 {
			return stWithDelay.Err()
		}
		return nil
	})
	if err != nil || called != 2 {
		t.Errorf("expected RetryWithBackoff to handle server RetryInfo delay, got err=%v, called=%d", err, called)
	}

	// 7. Context already canceled at start
	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	err = RetryWithBackoff(canceledCtx, DefaultBackoffConfig(), func() error {
		return nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got %v", err)
	}

	// 8. Context canceled during retry sleep
	ctxWithTimeout, cancelTimeout := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancelTimeout()
	cfgLongPause := BackoffConfig{
		InitialDelay: 500 * time.Millisecond,
		MaxDelay:     1 * time.Second,
		Multiplier:   2.0,
		MaxAttempts:  5,
	}
	err = RetryWithBackoff(ctxWithTimeout, cfgLongPause, func() error {
		return status.Error(codes.Unavailable, "try again")
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("expected context.DeadlineExceeded during backoff pause, got %v", err)
	}
}
