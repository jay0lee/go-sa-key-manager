//go:build live

package integration

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	admin "cloud.google.com/go/iam/admin/apiv1"
	"cloud.google.com/go/iam/admin/apiv1/adminpb"
	"github.com/jay0lee/go-sa-key-manager/cmd"
	"github.com/jay0lee/go-sa-key-manager/pkg/client"
)

type liveTestConfig struct {
	StandardProject string
	NoCreateProject string
	NoUploadProject string
	ExpiryProject   string
	RunnerID        string
}

func getLiveConfig(t *testing.T) liveTestConfig {
	stdProj := os.Getenv("GCP_PROJECT_STANDARD")
	if stdProj == "" {
		t.Skip("skipping live GCP integration tests: GCP_PROJECT_STANDARD environment variable not set")
	}

	runnerID := os.Getenv("GCP_RUNNER_ID")
	if runnerID == "" {
		runnerID = "local"
	}

	return liveTestConfig{
		StandardProject: stdProj,
		NoCreateProject: os.Getenv("GCP_PROJECT_NO_CREATE"),
		NoUploadProject: os.Getenv("GCP_PROJECT_NO_UPLOAD"),
		ExpiryProject:   os.Getenv("GCP_PROJECT_EXPIRY_24H"),
		RunnerID:        runnerID,
	}
}

// secureWipeAndRemoveDir securely zeroes all file bytes before removing the directory.
func secureWipeAndRemoveDir(dir string) {
	_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			if info.Size() > 0 {
				zeroes := make([]byte, info.Size())
				_ = os.WriteFile(path, zeroes, 0600)
			}
		}
		return nil
	})
	_ = os.RemoveAll(dir)
}

// revokeAllUserKeys deletes all user-managed keys on the specified service account resource.
func revokeAllUserKeys(ctx context.Context, iamClient *admin.IamClient, saResourceName string) int {
	keyReq := &adminpb.ListServiceAccountKeysRequest{
		Name: saResourceName,
		KeyTypes: []adminpb.ListServiceAccountKeysRequest_KeyType{
			adminpb.ListServiceAccountKeysRequest_USER_MANAGED,
		},
	}
	keyResp, err := iamClient.ListServiceAccountKeys(ctx, keyReq)
	if err != nil {
		return 0
	}
	revoked := 0
	for _, k := range keyResp.Keys {
		if err := iamClient.DeleteServiceAccountKey(ctx, &adminpb.DeleteServiceAccountKeyRequest{Name: k.Name}); err == nil {
			revoked++
		}
	}
	return revoked
}

// purgeStaleTestArtifacts purges any orphaned test service accounts and their keys from previous/stale runs.
func purgeStaleTestArtifacts(t *testing.T, ctx context.Context, iamClient *admin.IamClient, projectID, runnerID string) {
	t.Helper()
	req := &adminpb.ListServiceAccountsRequest{
		Name: "projects/" + projectID,
	}
	it := iamClient.ListServiceAccounts(ctx, req)
	prefix := fmt.Sprintf("test-%s-", strings.ReplaceAll(runnerID, "_", "-"))
	for {
		sa, err := it.Next()
		if err != nil {
			break
		}
		// Match test service accounts created strictly by this runner architecture
		if strings.HasPrefix(sa.Email, prefix) {
			// Extract timestamp suffix: test-<runner>-<timestamp>@...
			parts := strings.Split(strings.TrimPrefix(sa.Email, prefix), "@")
			if len(parts) > 0 {
				var ts int64
				if _, scanErr := fmt.Sscanf(parts[0], "%d", &ts); scanErr == nil && ts > 0 {
					// Protect actively running test steps created within the last 3 minutes
					if time.Since(time.Unix(ts, 0)) < 3*time.Minute {
						continue
					}
				}
			}
			keysRevoked := revokeAllUserKeys(ctx, iamClient, sa.Name)
			delErr := iamClient.DeleteServiceAccount(ctx, &adminpb.DeleteServiceAccountRequest{Name: sa.Name})
			t.Logf("[Pre-Test Cleanup] Purged stale SA %s (revoked %d keys, deleted: %v)", sa.Email, keysRevoked, delErr == nil)
		}
	}
}

// createEphemeralServiceAccount creates an ephemeral service account for testing and returns its email and cleanup func.
func createEphemeralServiceAccount(t *testing.T, ctx context.Context, projectID, runnerID string) (string, func()) {
	t.Helper()
	iamClient, err := admin.NewIamClient(ctx)
	if err != nil {
		t.Fatalf("failed to initialize IAM Admin client: %v", err)
	}

	// 1. Security requirement: Start by revoking any stale test keys and accounts from previous runs
	purgeStaleTestArtifacts(t, ctx, iamClient, projectID, runnerID)

	accountID := fmt.Sprintf("test-%s-%d", strings.ReplaceAll(runnerID, "_", "-"), time.Now().Unix())
	if len(accountID) > 30 {
		accountID = accountID[:30]
	}

	req := &adminpb.CreateServiceAccountRequest{
		Name:      "projects/" + projectID,
		AccountId: accountID,
		ServiceAccount: &adminpb.ServiceAccount{
			DisplayName: fmt.Sprintf("Live Test SA %s (%s)", accountID, runnerID),
		},
	}

	sa, err := iamClient.CreateServiceAccount(ctx, req)
	if err != nil {
		iamClient.Close()
		t.Fatalf("failed to create ephemeral test service account %s in %s: %v", accountID, projectID, err)
	}

	email := sa.Email
	t.Logf("Created ephemeral test service account: %s", email)

	// Explicitly verify zero user keys exist initially
	revokeAllUserKeys(ctx, iamClient, sa.Name)

	// Wait for newly created service account to propagate in IAM
	waitForServiceAccountReady(t, ctx, iamClient, email)

	cleanup := func() {
		defer iamClient.Close()
		// 2. Security requirement: Revoke and delete ALL user-managed keys at end of testing
		keysRevoked := revokeAllUserKeys(context.Background(), iamClient, sa.Name)
		t.Logf("[Post-Test Cleanup] Revoked %d user-managed keys on %s", keysRevoked, email)

		t.Logf("Deleting ephemeral test service account: %s", email)
		delReq := &adminpb.DeleteServiceAccountRequest{
			Name: "projects/" + projectID + "/serviceAccounts/" + email,
		}
		_ = iamClient.DeleteServiceAccount(context.Background(), delReq)
	}

	return email, cleanup
}

// waitForServiceAccountReady polls IAM until the newly created service account is queryable.
func waitForServiceAccountReady(t *testing.T, ctx context.Context, iamClient *admin.IamClient, saEmail string) {
	t.Helper()
	deadline := time.Now().Add(45 * time.Second)
	resourceName := "projects/-/serviceAccounts/" + saEmail
	for time.Now().Before(deadline) {
		_, err := iamClient.ListServiceAccountKeys(ctx, &adminpb.ListServiceAccountKeysRequest{
			Name: resourceName,
			KeyTypes: []adminpb.ListServiceAccountKeysRequest_KeyType{
				adminpb.ListServiceAccountKeysRequest_USER_MANAGED,
			},
		})
		if err == nil {
			t.Logf("Service account %s is propagated and accessible via %s", saEmail, resourceName)
			return
		}
		time.Sleep(2 * time.Second)
	}
	t.Logf("Warning: timed out waiting for %s to propagate", saEmail)
}

func executeCLI(args ...string) (string, string, error) {
	app := cmd.NewDefaultApp()
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	app.Out = stdout
	app.ErrOut = stderr

	root := cmd.NewRootCommand(app)
	root.SetArgs(args)

	err := root.Execute()
	return stdout.String(), stderr.String(), err
}

// TestLive_FullLifecycle_StandardProject exercises all tool operations in an unrestricted project.
func TestLive_FullLifecycle_StandardProject(t *testing.T) {
	cfg := getLiveConfig(t)
	ctx := context.Background()

	saEmail, cleanup := createEphemeralServiceAccount(t, ctx, cfg.StandardProject, cfg.RunnerID)
	defer cleanup()

	tmpDir := t.TempDir()
	defer secureWipeAndRemoveDir(tmpDir)

	// 1. Create GCP-managed key
	t.Run("1_CreateKey", func(t *testing.T) {
		credsPath := filepath.Join(tmpDir, "gcp-managed.json")
		var stdout, stderr string
		var err error
		for attempt := 0; attempt < 5; attempt++ {
			stdout, stderr, err = executeCLI("create", saEmail, "-o", credsPath)
			if err == nil {
				break
			}
			if strings.Contains(stderr, "does not exist") || strings.Contains(stderr, "PermissionDenied") {
				time.Sleep(2 * time.Second)
				continue
			}
			break
		}
		if err != nil {
			t.Fatalf("create failed: %v\nstderr: %s", err, stderr)
		}
		if !strings.Contains(strings.ToLower(stdout), "created gcp-managed key") {
			t.Errorf("unexpected stdout: %s", stdout)
		}
		if _, err := os.Stat(credsPath); err != nil {
			t.Fatalf("creds file not created: %v", err)
		}
	})

	// 2. List keys in JSON format
	var createdKeyID string
	t.Run("2_ListKeys", func(t *testing.T) {
		stdout, stderr, err := executeCLI("list", saEmail, "--type", "user", "-f", "json")
		if err != nil {
			t.Fatalf("list failed: %v\nstderr: %s", err, stderr)
		}
		var keys []client.KeyInfo
		if err := json.Unmarshal([]byte(stdout), &keys); err != nil {
			t.Fatalf("failed to parse json list output: %v\noutput: %s", err, stdout)
		}
		if len(keys) == 0 {
			t.Fatalf("expected at least 1 user key, found 0")
		}
		createdKeyID = keys[0].ID
		t.Logf("Found key ID: %s", createdKeyID)
	})

	// 3. Get key details and extract public key
	t.Run("3_GetKey", func(t *testing.T) {
		if createdKeyID == "" {
			t.Skip("createdKeyID not found")
		}
		pubKeyPath := filepath.Join(tmpDir, "key.pem")
		stdout, stderr, err := executeCLI("get", saEmail, createdKeyID, "--public-key", "-o", pubKeyPath)
		if err != nil {
			t.Fatalf("get failed: %v\nstderr: %s", err, stderr)
		}
		if !strings.Contains(strings.ToLower(stdout), "public key") {
			t.Errorf("unexpected get output: %s", stdout)
		}
		if _, err := os.Stat(pubKeyPath); err != nil {
			t.Fatalf("public key file not created: %v", err)
		}
	})

	// 4. Disable and Re-enable key
	t.Run("4_DisableAndEnableKey", func(t *testing.T) {
		if createdKeyID == "" {
			t.Skip("createdKeyID not found")
		}
		_, stderr, err := executeCLI("disable", saEmail, createdKeyID)
		if err != nil {
			t.Fatalf("disable failed: %v\nstderr: %s", err, stderr)
		}

		stdout, _, err := executeCLI("get", saEmail, createdKeyID, "-f", "json")
		if err != nil {
			t.Fatalf("get disabled failed: %v", err)
		}
		var keyInfo client.KeyInfo
		if err := json.Unmarshal([]byte(stdout), &keyInfo); err != nil {
			t.Fatalf("failed to parse key json: %v", err)
		}
		if !keyInfo.Disabled {
			t.Errorf("expected key to be disabled")
		}

		_, stderr, err = executeCLI("enable", saEmail, createdKeyID)
		if err != nil {
			t.Fatalf("enable failed: %v\nstderr: %s", err, stderr)
		}
	})

	// 5. Generate local 2048-bit key with custom validity
	t.Run("5_GenerateLocalKey", func(t *testing.T) {
		localCredsPath := filepath.Join(tmpDir, "local-creds.json")
		stdout, stderr, err := executeCLI("generate", saEmail,
			"--bits", "2048",
			"--validity-days", "30",
			"-o", localCredsPath,
		)
		if err != nil {
			t.Fatalf("generate failed: %v\nstderr: %s", err, stderr)
		}
		if !strings.Contains(stdout, "Successfully generated local RSA key") {
			t.Errorf("unexpected generate output: %s", stdout)
		}
		if _, err := os.Stat(localCredsPath); err != nil {
			t.Fatalf("local creds file not created: %v", err)
		}
	})

	// 6. Generate 1024-bit key (warning check)
	t.Run("6_Generate1024BitKeyWarning", func(t *testing.T) {
		local1024Path := filepath.Join(tmpDir, "local-1024.json")
		_, stderr, err := executeCLI("generate", saEmail,
			"--bits", "1024",
			"--validity-hours", "24",
			"-o", local1024Path,
		)
		if err != nil {
			t.Fatalf("generate 1024 failed: %v\nstderr: %s", err, stderr)
		}
		if !strings.Contains(stderr, "WARNING: 1024-bit RSA keys are deprecated") {
			t.Errorf("expected 1024-bit security warning in stderr, got: %s", stderr)
		}
	})

	// 7. Upload raw RSA public key with --wrap-rsa
	t.Run("7_UploadWrappedRSAPublicKey", func(t *testing.T) {
		rawKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("failed to generate raw RSA key: %v", err)
		}
		pubBytes, err := x509.MarshalPKIXPublicKey(&rawKey.PublicKey)
		if err != nil {
			t.Fatalf("failed to marshal public key: %v", err)
		}
		pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})
		rawPubPath := filepath.Join(tmpDir, "hsm-pub.pem")
		if err := os.WriteFile(rawPubPath, pubPEM, 0600); err != nil {
			t.Fatalf("failed to write pub PEM: %v", err)
		}

		stdout, stderr, err := executeCLI("upload", saEmail, rawPubPath, "--wrap-rsa", "--wrap-validity", "168h")
		if err != nil {
			t.Fatalf("upload wrapped rsa failed: %v\nstderr: %s", err, stderr)
		}
		if !strings.Contains(strings.ToLower(stdout), "uploaded public key") {
			t.Errorf("unexpected upload stdout: %s", stdout)
		}
	})

	// 8. Rotate keys (both local and gcp methods)
	t.Run("8_RotateKeys", func(t *testing.T) {
		rotLocalPath := filepath.Join(tmpDir, "rot-local.json")
		stdout, stderr, err := executeCLI("rotate", saEmail,
			"--method", "local",
			"--validity", "720h",
			"--disable-old",
			"-o", rotLocalPath,
		)
		if err != nil {
			t.Fatalf("rotate local failed: %v\nstderr: %s", err, stderr)
		}
		if !strings.Contains(stdout, "Key rotation completed successfully") {
			t.Errorf("unexpected rotate output: %s", stdout)
		}

		rotGcpPath := filepath.Join(tmpDir, "rot-gcp.json")
		stdout, stderr, err = executeCLI("rotate", saEmail,
			"--method", "gcp",
			"--delete-old",
			"-o", rotGcpPath,
		)
		if err != nil {
			t.Fatalf("rotate gcp failed: %v\nstderr: %s", err, stderr)
		}
		if !strings.Contains(stdout, "Key rotation completed successfully") {
			t.Errorf("unexpected rotate gcp output: %s", stdout)
		}
	})

	// 9. Delete remaining keys
	t.Run("9_DeleteRemainingKeys", func(t *testing.T) {
		stdout, _, err := executeCLI("list", saEmail, "--type", "user", "-f", "json")
		if err != nil {
			t.Fatalf("list failed: %v", err)
		}
		var keys []client.KeyInfo
		_ = json.Unmarshal([]byte(stdout), &keys)
		for _, k := range keys {
			_, stderr, err := executeCLI("delete", saEmail, k.ID)
			if err != nil {
				t.Logf("delete key %s warning: %v\nstderr: %s", k.ID, err, stderr)
			}
		}
	})
}

// TestLive_Policy_NoCreate verifies constraints/iam.disableServiceAccountKeyCreation rejection.
func TestLive_Policy_NoCreate(t *testing.T) {
	cfg := getLiveConfig(t)
	if cfg.NoCreateProject == "" {
		t.Skip("skipping no-create policy test: GCP_PROJECT_NO_CREATE not set")
	}
	ctx := context.Background()

	saEmail, cleanup := createEphemeralServiceAccount(t, ctx, cfg.NoCreateProject, cfg.RunnerID)
	defer cleanup()

	tmpDir := t.TempDir()
	defer secureWipeAndRemoveDir(tmpDir)

	// 1. GCP-managed key creation MUST FAIL with friendly policy violation
	t.Run("Create_ShouldFailPolicy", func(t *testing.T) {
		credsPath := filepath.Join(tmpDir, "should-fail.json")
		_, stderr, err := executeCLI("create", saEmail, "-o", credsPath)
		if err == nil {
			t.Fatalf("expected create to fail due to disableServiceAccountKeyCreation policy, but it succeeded")
		}
		if !strings.Contains(stderr, "disableServiceAccountKeyCreation") && !strings.Contains(stderr, "not allowed") {
			t.Errorf("expected friendly disableServiceAccountKeyCreation error, got stderr: %s", stderr)
		}
	})

	// 2. Rotate with --method=gcp MUST FAIL
	t.Run("RotateGCP_ShouldFailPolicy", func(t *testing.T) {
		rotPath := filepath.Join(tmpDir, "rot-fail.json")
		_, stderr, err := executeCLI("rotate", saEmail, "--method", "gcp", "-o", rotPath)
		if err == nil {
			t.Fatalf("expected rotate gcp to fail due to policy, but it succeeded")
		}
		if !strings.Contains(stderr, "Organization Policy") && !strings.Contains(stderr, "not allowed") {
			t.Errorf("expected policy error in stderr, got: %s", stderr)
		}
	})

	// 3. Local key generation MUST SUCCEED (uploading public cert is allowed when key creation is blocked)
	t.Run("Generate_ShouldSucceed", func(t *testing.T) {
		localPath := filepath.Join(tmpDir, "local-ok.json")
		_, stderr, err := executeCLI("generate", saEmail, "--validity-days", "7", "-o", localPath)
		if err != nil {
			t.Fatalf("expected generate to succeed in no-create project, but failed: %v\nstderr: %s", err, stderr)
		}
	})
}

// TestLive_Policy_NoUpload verifies constraints/iam.disableServiceAccountKeyUpload rejection.
func TestLive_Policy_NoUpload(t *testing.T) {
	cfg := getLiveConfig(t)
	if cfg.NoUploadProject == "" {
		t.Skip("skipping no-upload policy test: GCP_PROJECT_NO_UPLOAD not set")
	}
	ctx := context.Background()

	saEmail, cleanup := createEphemeralServiceAccount(t, ctx, cfg.NoUploadProject, cfg.RunnerID)
	defer cleanup()

	tmpDir := t.TempDir()
	defer secureWipeAndRemoveDir(tmpDir)

	// 1. Local key generate MUST FAIL (uploading public cert is blocked)
	t.Run("Generate_ShouldFailPolicy", func(t *testing.T) {
		localPath := filepath.Join(tmpDir, "local-fail.json")
		_, stderr, err := executeCLI("generate", saEmail, "--validity-days", "7", "-o", localPath)
		if err == nil {
			t.Fatalf("expected generate to fail due to disableServiceAccountKeyUpload policy, but it succeeded")
		}
		if !strings.Contains(stderr, "Organization Policy") && !strings.Contains(stderr, "disableServiceAccountKeyUpload") {
			t.Errorf("expected friendly disableServiceAccountKeyUpload error, got stderr: %s", stderr)
		}
	})

	// 2. GCP-managed key creation MUST SUCCEED
	t.Run("Create_ShouldSucceed", func(t *testing.T) {
		credsPath := filepath.Join(tmpDir, "gcp-ok.json")
		_, stderr, err := executeCLI("create", saEmail, "-o", credsPath)
		if err != nil {
			t.Fatalf("expected create to succeed in no-upload project, but failed: %v\nstderr: %s", err, stderr)
		}
	})
}

// TestLive_Policy_KeyExpiryHours verifies constraints/iam.serviceAccountKeyExpiryHours rejection.
func TestLive_Policy_KeyExpiryHours(t *testing.T) {
	cfg := getLiveConfig(t)
	if cfg.ExpiryProject == "" {
		t.Skip("skipping expiry policy test: GCP_PROJECT_EXPIRY_24H not set")
	}
	ctx := context.Background()

	saEmail, cleanup := createEphemeralServiceAccount(t, ctx, cfg.ExpiryProject, cfg.RunnerID)
	defer cleanup()

	tmpDir := t.TempDir()
	defer secureWipeAndRemoveDir(tmpDir)

	// 1. Key generation with 720h (30 days > 24 hours) MUST FAIL with policy violation
	t.Run("Generate_ExceedsExpiry_ShouldFailPolicy", func(t *testing.T) {
		localPath := filepath.Join(tmpDir, "expiry-fail.json")
		_, stderr, err := executeCLI("generate", saEmail, "--validity", "720h", "-o", localPath)
		if err == nil {
			t.Fatalf("expected generate with 720h to fail in 24h expiry project, but it succeeded")
		}
		if !strings.Contains(stderr, "Organization Policy") && !strings.Contains(stderr, "serviceAccountKeyExpiryHours") {
			t.Errorf("expected friendly serviceAccountKeyExpiryHours error, got stderr: %s", stderr)
		}
	})

	// 2. Key generation with 12h (<= 24 hours) MUST SUCCEED
	t.Run("Generate_WithinExpiry_ShouldSucceed", func(t *testing.T) {
		localPath := filepath.Join(tmpDir, "expiry-ok.json")
		_, stderr, err := executeCLI("generate", saEmail, "--validity", "12h", "-o", localPath)
		if err != nil {
			t.Fatalf("expected generate with 12h to succeed in 24h expiry project, but failed: %v\nstderr: %s", err, stderr)
		}
	})
}
