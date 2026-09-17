//go:build live

package integration

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// getBinaryPath returns the path to the compiled gcp-sa-key-manager binary.
func getBinaryPath(t *testing.T) string {
	t.Helper()
	binName := "gcp-sa-key-manager"
	if runtime.GOOS == "windows" {
		binName += ".exe"
	}

	// Look in ./bin first (relative to project root)
	cwd, _ := os.Getwd()
	projRoot := filepath.Dir(filepath.Dir(cwd))
	binPath := filepath.Join(projRoot, "bin", binName)

	if _, err := os.Stat(binPath); err != nil {
		// Build binary on-the-fly into temp dir
		tmpBin := filepath.Join(t.TempDir(), binName)
		cmd := exec.Command("go", "build", "-o", tmpBin, filepath.Join(projRoot, "main.go"))
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("failed to build binary for cli test: %v\noutput: %s", err, out)
		}
		return tmpBin
	}

	return binPath
}

// TestLive_CLI_BinaryExecution tests calling the actual compiled binary as an external subprocess.
func TestLive_CLI_BinaryExecution(t *testing.T) {
	cfg := getLiveConfig(t)
	binPath := getBinaryPath(t)
	ctx := context.Background()

	saEmail, cleanup := createEphemeralServiceAccount(t, ctx, cfg.StandardProject, cfg.RunnerID)
	defer cleanup()

	tmpDir := t.TempDir()

	// 1. Version check
	t.Run("CLI_Version", func(t *testing.T) {
		cmd := exec.Command(binPath, "version", "-f", "json")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("version failed: %v\noutput: %s", err, out)
		}
		if !strings.Contains(string(out), `"version"`) {
			t.Errorf("unexpected version output: %s", out)
		}
	})

	// 2. Create key via binary subprocess
	t.Run("CLI_CreateKey", func(t *testing.T) {
		credsPath := filepath.Join(tmpDir, "cli-creds.json")
		cmd := exec.Command(binPath, "create", saEmail, "-o", credsPath)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("cli create failed: %v\nstderr: %s", err, stderr.String())
		}
		if !strings.Contains(string(out), "Created GCP-managed key") {
			t.Errorf("unexpected output: %s", out)
		}
	})

	// 3. List keys via binary subprocess (table format)
	t.Run("CLI_ListKeys", func(t *testing.T) {
		cmd := exec.Command(binPath, "list", saEmail)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("cli list failed: %v\noutput: %s", err, out)
		}
		if !strings.Contains(string(out), "KEY ID") {
			t.Errorf("expected table header in output: %s", out)
		}
	})
}
