package main

import (
	"os"
	"testing"
)

func TestMainExecution(t *testing.T) {
	origArgs := os.Args
	defer func() { os.Args = origArgs }()

	// Test run with "version" argument
	os.Args = []string{"gcp-sa-key-manager", "version"}
	code := run()
	if code != 0 {
		t.Fatalf("expected exit code 0 for version, got %d", code)
	}

	// Test run with invalid command
	os.Args = []string{"gcp-sa-key-manager", "nonexistent-cmd"}
	code = run()
	if code != 1 {
		t.Fatalf("expected exit code 1 for invalid command, got %d", code)
	}

	// Test main() invoking exitFunc
	origExit := exitFunc
	defer func() { exitFunc = origExit }()

	var capturedCode int
	exitFunc = func(code int) {
		capturedCode = code
	}

	os.Args = []string{"gcp-sa-key-manager", "version"}
	main()
	if capturedCode != 0 {
		t.Fatalf("expected captured exit code 0, got %d", capturedCode)
	}
}
