package output

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jay0lee/go-sa-key-manager/pkg/client"
)

type failWriter struct{}

func (failWriter) Write(p []byte) (n int, err error) {
	return 0, errors.New("write failure")
}

func TestCalculateRemainingValidity(t *testing.T) {
	now := time.Now()

	// Expired
	if res := CalculateRemainingValidity(now.Add(-10 * time.Minute)); res != "Expired" {
		t.Fatalf("expected 'Expired', got %q", res)
	}

	// Days
	if res := CalculateRemainingValidity(now.Add(50 * time.Hour)); !strings.Contains(res, "d") {
		t.Fatalf("expected days in %q", res)
	}

	// Hours (< 24h, > 1h)
	if res := CalculateRemainingValidity(now.Add(5 * time.Hour)); !strings.Contains(res, "h") {
		t.Fatalf("expected hours in %q", res)
	}

	// Minutes (< 1h)
	if res := CalculateRemainingValidity(now.Add(25 * time.Minute)); !strings.Contains(res, "m") {
		t.Fatalf("expected minutes in %q", res)
	}
}

func TestFormatOutput_TableKeys(t *testing.T) {
	now := time.Now()
	keys := []*client.KeyInfo{
		{
			ID:              "key-active",
			Name:            "projects/-/keys/key-active",
			KeyType:         client.KeyTypeUserManaged,
			KeyAlgorithm:    "RSA_2048",
			ValidAfterTime:  now.Add(-24 * time.Hour),
			ValidBeforeTime: now.Add(24 * time.Hour),
			Disabled:        false,
		},
		{
			ID:              "key-disabled",
			Name:            "projects/-/keys/key-disabled",
			KeyType:         client.KeyTypeUserManaged,
			KeyAlgorithm:    "RSA_2048",
			ValidAfterTime:  now.Add(-24 * time.Hour),
			ValidBeforeTime: now.Add(24 * time.Hour),
			Disabled:        true,
		},
		{
			ID:              "key-expired",
			Name:            "projects/-/keys/key-expired",
			KeyType:         client.KeyTypeUserManaged,
			KeyAlgorithm:    "RSA_2048",
			ValidAfterTime:  now.Add(-48 * time.Hour),
			ValidBeforeTime: now.Add(-24 * time.Hour),
			Disabled:        false,
		},
	}

	var buf bytes.Buffer
	if err := FormatOutput(&buf, "table", keys); err != nil {
		t.Fatalf("unexpected table format error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "key-active") || !strings.Contains(out, "ACTIVE") ||
		!strings.Contains(out, "key-disabled") || !strings.Contains(out, "DISABLED") ||
		!strings.Contains(out, "key-expired") || !strings.Contains(out, "EXPIRED") {
		t.Fatalf("missing expected status or key in table output: %s", out)
	}

	// Default empty format defaults to table
	buf.Reset()
	if err := FormatOutput(&buf, "", keys); err != nil {
		t.Fatalf("unexpected default table format error: %v", err)
	}
	if !strings.Contains(buf.String(), "key-active") {
		t.Fatalf("expected table format for empty string format")
	}
}

func TestFormatOutput_TableSingleKey(t *testing.T) {
	now := time.Now()

	// Active single key
	kActive := &client.KeyInfo{
		ID:              "key-1",
		Name:            "projects/-/keys/key-1",
		KeyType:         client.KeyTypeUserManaged,
		KeyAlgorithm:    "RSA_2048",
		ValidAfterTime:  now.Add(-1 * time.Hour),
		ValidBeforeTime: now.Add(24 * time.Hour),
		Disabled:        false,
	}
	var buf bytes.Buffer
	if err := FormatOutput(&buf, "table", kActive); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(buf.String(), "ACTIVE") {
		t.Fatalf("expected ACTIVE in single key table output: %s", buf.String())
	}

	// Disabled single key
	kDisabled := &client.KeyInfo{
		ID:              "key-2",
		Name:            "projects/-/keys/key-2",
		KeyType:         client.KeyTypeUserManaged,
		KeyAlgorithm:    "RSA_2048",
		ValidAfterTime:  now.Add(-1 * time.Hour),
		ValidBeforeTime: now.Add(24 * time.Hour),
		Disabled:        true,
	}
	buf.Reset()
	if err := FormatOutput(&buf, "table", kDisabled); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(buf.String(), "DISABLED") {
		t.Fatalf("expected DISABLED in single key table output: %s", buf.String())
	}

	// Expired single key
	kExpired := &client.KeyInfo{
		ID:              "key-3",
		Name:            "projects/-/keys/key-3",
		KeyType:         client.KeyTypeUserManaged,
		KeyAlgorithm:    "RSA_2048",
		ValidAfterTime:  now.Add(-10 * time.Hour),
		ValidBeforeTime: now.Add(-1 * time.Hour),
		Disabled:        false,
	}
	buf.Reset()
	if err := FormatOutput(&buf, "table", kExpired); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(buf.String(), "EXPIRED") {
		t.Fatalf("expected EXPIRED in single key table output: %s", buf.String())
	}
}

func TestFormatOutput_FallbackTable(t *testing.T) {
	var buf bytes.Buffer
	custom := map[string]string{"foo": "bar"}
	if err := FormatOutput(&buf, "table", custom); err != nil {
		t.Fatalf("unexpected fallback error: %v", err)
	}
	if !strings.Contains(buf.String(), `"foo": "bar"`) {
		t.Fatalf("expected json fallback, got: %s", buf.String())
	}
}

func TestFormatOutput_JSON(t *testing.T) {
	var buf bytes.Buffer
	data := map[string]string{"message": "success"}
	if err := FormatOutput(&buf, "json", data); err != nil {
		t.Fatalf("unexpected json error: %v", err)
	}
	if !strings.Contains(buf.String(), `"message": "success"`) {
		t.Fatalf("unexpected json output: %s", buf.String())
	}

	// Test JSON encode error
	if err := PrintJSON(failWriter{}, data); err == nil {
		t.Fatalf("expected error from failWriter in PrintJSON")
	}
}

func TestFormatOutput_YAML(t *testing.T) {
	var buf bytes.Buffer
	data := map[string]string{"message": "success"}
	if err := FormatOutput(&buf, "yaml", data); err != nil {
		t.Fatalf("unexpected yaml error: %v", err)
	}
	if !strings.Contains(buf.String(), "message: success") {
		t.Fatalf("unexpected yaml output: %s", buf.String())
	}

	// Test YAML encode error
	if err := PrintYAML(failWriter{}, data); err == nil {
		t.Fatalf("expected error from failWriter in PrintYAML")
	}
}

func TestFormatOutput_Unsupported(t *testing.T) {
	var buf bytes.Buffer
	if err := FormatOutput(&buf, "xml", "data"); err == nil {
		t.Fatalf("expected error for unsupported format 'xml'")
	}
}
