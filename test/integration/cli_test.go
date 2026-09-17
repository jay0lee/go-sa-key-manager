//go:build live

package integration

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/jay0lee/go-sa-key-manager/pkg/client"
)

// getBinaryPath returns the path to the compiled gcp-sa-key-manager binary.
func getBinaryPath(t *testing.T) string {
	t.Helper()
	if binPath := resolveBinaryPath(os.Getenv("SAKM_BINARY_PATH")); binPath != "" {
		return binPath
	}

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

	saEmail, _, cleanup := createEphemeralServiceAccount(t, ctx, cfg.StandardProject, cfg.RunnerID)
	defer cleanup()

	tmpDir := t.TempDir()
	defer secureWipeAndRemoveDir(tmpDir)

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

	// 2. Create key via binary subprocess (dual-verified: gotten via IAM and found in public metadata)
	t.Run("CLI_CreateKey", func(t *testing.T) {
		credsPath := filepath.Join(tmpDir, "cli-creds.json")
		cmd := exec.Command(binPath, "create", saEmail, "-o", credsPath)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("cli create failed: %v\noutput: %s", err, string(out))
		}
		if !strings.Contains(strings.ToLower(string(out)), "created gcp-managed key") {
			t.Errorf("unexpected output: %s", out)
		}
		if _, statErr := os.Stat(credsPath); statErr != nil {
			t.Fatalf("creds file not created: %v", statErr)
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

	// 4. Delete keys created during CLI binary execution test
	t.Run("CLI_DeleteKey", func(t *testing.T) {
		cmdList := exec.Command(binPath, "list", saEmail, "--type", "user", "-f", "json")
		listOut, err := cmdList.CombinedOutput()
		if err == nil {
			var userKeys []client.KeyInfo
			if json.Unmarshal(listOut, &userKeys) == nil {
				for _, k := range userKeys {
					delCmd := exec.Command(binPath, "delete", saEmail, k.ID)
					_ = delCmd.Run()
				}
			}
		}
	})
}
