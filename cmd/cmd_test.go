package cmd

import (
	"bytes"
	"context"
	cryptopkg "crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jay0lee/go-sa-key-manager/pkg/client"
	"github.com/jay0lee/go-sa-key-manager/pkg/crypto"
)

type testEnv struct {
	app        *App
	mockClient *client.MockIAMClient
	files      map[string][]byte
	stdout     *bytes.Buffer
	stderr     *bytes.Buffer
}

func newTestEnv() *testEnv {
	mock := client.NewMockIAMClient()
	files := make(map[string][]byte)
	stdout := new(bytes.Buffer)
	stderr := new(bytes.Buffer)

	app := &App{
		In:     strings.NewReader(""),
		Out:    stdout,
		ErrOut: stderr,
		ClientFactory: func(ctx context.Context, credentialsFile string) (client.IAMClient, error) {
			return mock, nil
		},
		OSWriteFile: func(filename string, data []byte, perm os.FileMode) error {
			files[filename] = data
			return nil
		},
		OSReadFile: func(filename string) ([]byte, error) {
			data, ok := files[filename]
			if !ok {
				return nil, os.ErrNotExist
			}
			return data, nil
		},
		Crypto: CryptoOps{
			GenerateRSAKeyPair:          crypto.GenerateRSAKeyPair,
			CreateSelfSignedCertificate: crypto.CreateSelfSignedCertificate,
			EncodePrivateKeyToPKCS8PEM:  crypto.EncodePrivateKeyToPKCS8PEM,
			BuildGCPCredentialsJSON:     crypto.BuildGCPCredentialsJSON,
			WrapRSAPublicKeyInCert:      crypto.WrapRSAPublicKeyInCert,
		},
		Format: "table",
	}

	return &testEnv{
		app:        app,
		mockClient: mock,
		files:      files,
		stdout:     stdout,
		stderr:     stderr,
	}
}

func executeCommand(app *App, args ...string) error {
	rootCmd := NewRootCommand(app)
	rootCmd.SetArgs(args)
	return rootCmd.Execute()
}

func TestNewDefaultAppAndRoot(t *testing.T) {
	app := NewDefaultApp()
	if app == nil || app.OSWriteFile == nil || app.OSReadFile == nil || app.ClientFactory == nil {
		t.Fatalf("unexpected nil in NewDefaultApp: %+v", app)
	}

	// Test NewRootCommand with nil (should default)
	root := NewRootCommand(nil)
	if root == nil {
		t.Fatalf("expected non-nil root command")
	}

	// Test ClientFactory from NewDefaultApp
	c, _ := app.ClientFactory(context.Background(), "")
	if c != nil {
		_ = c.Close()
	}
}

func TestParseValidityDuration(t *testing.T) {
	// Hours > 0
	dur, err := parseValidityDuration("100h", 0, 5)
	if err != nil || dur != 5*time.Hour {
		t.Fatalf("expected 5h, got %v, err: %v", dur, err)
	}

	// Days > 0
	dur, err = parseValidityDuration("100h", 3, 0)
	if err != nil || dur != 72*time.Hour {
		t.Fatalf("expected 72h, got %v, err: %v", dur, err)
	}

	// Empty string defaults to 2160h
	dur, err = parseValidityDuration("", 0, 0)
	if err != nil || dur != 2160*time.Hour {
		t.Fatalf("expected 2160h default, got %v, err: %v", dur, err)
	}

	// Day suffix string "30d"
	dur, err = parseValidityDuration("30d", 0, 0)
	if err != nil || dur != 30*24*time.Hour {
		t.Fatalf("expected 30 days, got %v, err: %v", dur, err)
	}

	// Standard duration string "48h"
	dur, err = parseValidityDuration("48h", 0, 0)
	if err != nil || dur != 48*time.Hour {
		t.Fatalf("expected 48h, got %v, err: %v", dur, err)
	}

	// Invalid string
	if _, err := parseValidityDuration("invalid", 0, 0); err == nil {
		t.Fatalf("expected error for invalid duration string")
	}

	// Non-positive duration
	if _, err := parseValidityDuration("-5h", 0, 0); err == nil {
		t.Fatalf("expected error for negative duration")
	}
}

func TestListCommand(t *testing.T) {
	env := newTestEnv()
	sa := "sa@proj.iam.gserviceaccount.com"

	// Missing arg
	if err := executeCommand(env.app, "list"); err == nil {
		t.Fatalf("expected error for missing arg")
	}

	// Empty email
	if err := executeCommand(env.app, "list", "   "); err == nil {
		t.Fatalf("expected error for whitespace email")
	}

	// Invalid filter type
	if err := executeCommand(env.app, "list", sa, "--type", "invalid"); err == nil {
		t.Fatalf("expected error for invalid type filter")
	}

	// ClientFactory failure
	env.app.ClientFactory = func(ctx context.Context, credentialsFile string) (client.IAMClient, error) {
		return nil, errors.New("client init failed")
	}
	if err := executeCommand(env.app, "list", sa); err == nil {
		t.Fatalf("expected client factory error")
	}

	// Restore ClientFactory
	env.app.ClientFactory = func(ctx context.Context, credentialsFile string) (client.IAMClient, error) {
		return env.mockClient, nil
	}

	// ListKeys failure
	env.mockClient.ListKeysErr = errors.New("list keys failure")
	if err := executeCommand(env.app, "list", sa); err == nil {
		t.Fatalf("expected ListKeys error")
	}
	env.mockClient.ListKeysErr = nil

	// Successful list with keys
	_, _ = env.mockClient.CreateKey(context.Background(), sa)
	env.mockClient.AddKey(sa, &client.KeyInfo{ID: "sys-1", KeyType: client.KeyTypeSystemManaged})

	// User filter
	if err := executeCommand(env.app, "list", sa, "--type", "user"); err != nil {
		t.Fatalf("unexpected list user error: %v", err)
	}

	// System filter
	if err := executeCommand(env.app, "list", sa, "--type", "system"); err != nil {
		t.Fatalf("unexpected list system error: %v", err)
	}

	// All filter
	if err := executeCommand(env.app, "list", sa, "--type", "all"); err != nil {
		t.Fatalf("unexpected list all error: %v", err)
	}
}

func TestGetCommand(t *testing.T) {
	env := newTestEnv()
	sa := "sa@proj.iam.gserviceaccount.com"

	// Missing args
	if err := executeCommand(env.app, "get"); err == nil {
		t.Fatalf("expected error for missing args")
	}

	// Empty email / keyID
	if err := executeCommand(env.app, "get", "  ", "k1"); err == nil {
		t.Fatalf("expected error for empty email")
	}
	if err := executeCommand(env.app, "get", sa, "  "); err == nil {
		t.Fatalf("expected error for empty keyID")
	}

	// ClientFactory error
	env.app.ClientFactory = func(ctx context.Context, credentialsFile string) (client.IAMClient, error) {
		return nil, errors.New("client init failed")
	}
	if err := executeCommand(env.app, "get", sa, "k1"); err == nil {
		t.Fatalf("expected client factory error")
	}
	env.app.ClientFactory = func(ctx context.Context, credentialsFile string) (client.IAMClient, error) {
		return env.mockClient, nil
	}

	// Key not found
	if err := executeCommand(env.app, "get", sa, "nonexistent"); err == nil {
		t.Fatalf("expected not found error")
	}

	// Add key
	k := &client.KeyInfo{
		ID:            "k1",
		Name:          "projects/-/keys/k1",
		KeyType:       client.KeyTypeUserManaged,
		PublicKeyData: []byte("public-key-pem-content"),
	}
	env.mockClient.AddKey(sa, k)

	// Successful get table
	if err := executeCommand(env.app, "get", sa, "k1"); err != nil {
		t.Fatalf("unexpected get error: %v", err)
	}

	// Get public key to stdout
	env.stdout.Reset()
	if err := executeCommand(env.app, "get", sa, "k1", "--public-key"); err != nil {
		t.Fatalf("unexpected get public-key error: %v", err)
	}
	if !strings.Contains(env.stdout.String(), "public-key-pem-content") {
		t.Fatalf("missing public key in output: %s", env.stdout.String())
	}

	// Get public key to file
	if err := executeCommand(env.app, "get", sa, "k1", "--public-key", "--out", "pub.pem"); err != nil {
		t.Fatalf("unexpected get public-key out error: %v", err)
	}
	if string(env.files["pub.pem"]) != "public-key-pem-content" {
		t.Fatalf("file content mismatch")
	}

	// Write file error
	env.app.OSWriteFile = func(filename string, data []byte, perm os.FileMode) error {
		return errors.New("write failed")
	}
	if err := executeCommand(env.app, "get", sa, "k1", "--public-key", "--out", "pub.pem"); err == nil {
		t.Fatalf("expected write file error")
	}
	env.app.OSWriteFile = func(filename string, data []byte, perm os.FileMode) error {
		env.files[filename] = data
		return nil
	}

	// Key without public key data
	kNoPub := &client.KeyInfo{ID: "k-no-pub"}
	env.mockClient.AddKey(sa, kNoPub)
	if err := executeCommand(env.app, "get", sa, "k-no-pub", "--public-key"); err == nil {
		t.Fatalf("expected error for key with no public key")
	}
}

func TestCreateCommand(t *testing.T) {
	env := newTestEnv()
	sa := "sa@proj.iam.gserviceaccount.com"

	// Missing arg
	if err := executeCommand(env.app, "create"); err == nil {
		t.Fatalf("expected error for missing arg")
	}

	// Empty email
	if err := executeCommand(env.app, "create", "  "); err == nil {
		t.Fatalf("expected error for empty email")
	}

	// ClientFactory failure
	env.app.ClientFactory = func(ctx context.Context, credentialsFile string) (client.IAMClient, error) {
		return nil, errors.New("client init failed")
	}
	if err := executeCommand(env.app, "create", sa); err == nil {
		t.Fatalf("expected client factory error")
	}
	env.app.ClientFactory = func(ctx context.Context, credentialsFile string) (client.IAMClient, error) {
		return env.mockClient, nil
	}

	// CreateKey failure
	env.mockClient.CreateKeyErr = errors.New("create failed")
	if err := executeCommand(env.app, "create", sa); err == nil {
		t.Fatalf("expected CreateKey error")
	}
	env.mockClient.CreateKeyErr = nil

	// Successful create with default out file
	if err := executeCommand(env.app, "create", sa); err != nil {
		t.Fatalf("unexpected create error: %v", err)
	}

	// Successful create with stdout (-)
	env.stdout.Reset()
	if err := executeCommand(env.app, "create", sa, "--out", "-"); err != nil {
		t.Fatalf("unexpected create stdout error: %v", err)
	}
	if !strings.Contains(env.stdout.String(), "service_account") {
		t.Fatalf("expected service_account JSON in stdout: %s", env.stdout.String())
	}

	// Write file error
	env.app.OSWriteFile = func(filename string, data []byte, perm os.FileMode) error {
		return errors.New("write failed")
	}
	if err := executeCommand(env.app, "create", sa, "--out", "target.json"); err == nil {
		t.Fatalf("expected write file error")
	}
	env.app.OSWriteFile = func(filename string, data []byte, perm os.FileMode) error {
		env.files[filename] = data
		return nil
	}

	// Response without private key data
	env.mockClient.CreateKeyErr = nil
	origCreate := env.mockClient
	_ = origCreate
	// Custom mock client to return key with empty private key
	badKeyMock := client.NewMockIAMClient()
	env.app.ClientFactory = func(ctx context.Context, credentialsFile string) (client.IAMClient, error) {
		return badKeyMock, nil
	}
	// We override CreateKey using the fact that MockIAMClient allows setting empty PrivateKeyData
	badKeyMock.CreateKeyErr = nil
	// Let's create key then set PrivateKeyData to empty
	bk, _ := badKeyMock.CreateKey(context.Background(), sa)
	bk.PrivateKeyData = nil
	// Now call command
	badKeyMock.CreateKeyErr = nil
	// To return key with empty PrivateKeyData on CreateKey call:
	// We can subclass or define a custom client
}

type emptyKeyMock struct {
	*client.MockIAMClient
}

func (e *emptyKeyMock) CreateKey(ctx context.Context, saEmail string) (*client.KeyInfo, error) {
	return &client.KeyInfo{ID: "empty-key"}, nil
}

func TestCreateCommand_EmptyPrivateKeyData(t *testing.T) {
	env := newTestEnv()
	sa := "sa@proj.iam.gserviceaccount.com"
	env.app.ClientFactory = func(ctx context.Context, credentialsFile string) (client.IAMClient, error) {
		return &emptyKeyMock{MockIAMClient: env.mockClient}, nil
	}
	if err := executeCommand(env.app, "create", sa); err == nil {
		t.Fatalf("expected error for empty private key data")
	}
}

func TestGenerateCommand(t *testing.T) {
	env := newTestEnv()
	sa := "sa@proj.iam.gserviceaccount.com"

	// Missing arg
	if err := executeCommand(env.app, "generate"); err == nil {
		t.Fatalf("expected error for missing arg")
	}

	// Empty email
	if err := executeCommand(env.app, "generate", "  "); err == nil {
		t.Fatalf("expected error for empty email")
	}

	// Invalid validity
	if err := executeCommand(env.app, "generate", sa, "--validity", "invalid"); err == nil {
		t.Fatalf("expected error for invalid validity")
	}

	// Invalid bits
	if err := executeCommand(env.app, "generate", sa, "--bits", "512"); err == nil {
		t.Fatalf("expected error for 512 bits")
	}

	// 1024 bits with warning
	env.stderr.Reset()
	if err := executeCommand(env.app, "generate", sa, "--bits", "1024", "--out-credentials", "-"); err != nil {
		t.Fatalf("unexpected error for 1024 bits: %v", err)
	}
	if !strings.Contains(env.stderr.String(), "WARNING: 1024-bit RSA keys are deprecated") {
		t.Fatalf("expected warning for 1024 bits in stderr: %s", env.stderr.String())
	}

	// ClientFactory failure
	env.app.ClientFactory = func(ctx context.Context, credentialsFile string) (client.IAMClient, error) {
		return nil, errors.New("client init failed")
	}
	if err := executeCommand(env.app, "generate", sa); err == nil {
		t.Fatalf("expected client factory error")
	}
	env.app.ClientFactory = func(ctx context.Context, credentialsFile string) (client.IAMClient, error) {
		return env.mockClient, nil
	}

	// UploadKey failure
	env.mockClient.UploadKeyErr = errors.New("upload key failed")
	if err := executeCommand(env.app, "generate", sa); err == nil {
		t.Fatalf("expected UploadKey error")
	}
	env.mockClient.UploadKeyErr = nil

	// Successful generation with stdout (-)
	env.stdout.Reset()
	if err := executeCommand(env.app, "generate", sa, "--out-credentials", "-"); err != nil {
		t.Fatalf("unexpected generate stdout error: %v", err)
	}
	if !strings.Contains(env.stdout.String(), "service_account") {
		t.Fatalf("expected JSON credentials in stdout")
	}

	// Successful generation with all file flags
	if err := executeCommand(env.app, "generate", sa,
		"--validity-days", "30",
		"--out-credentials", "creds.json",
		"--out-key", "key.pem",
		"--out-cert", "cert.pem",
		"--common-name", "custom-cn",
	); err != nil {
		t.Fatalf("unexpected full generate error: %v", err)
	}
	if len(env.files["creds.json"]) == 0 || len(env.files["key.pem"]) == 0 || len(env.files["cert.pem"]) == 0 {
		t.Fatalf("missing generated files in testEnv")
	}

	// Write credentials failure
	env.app.OSWriteFile = func(filename string, data []byte, perm os.FileMode) error {
		if filename == "creds.json" {
			return errors.New("write creds failed")
		}
		return nil
	}
	if err := executeCommand(env.app, "generate", sa, "--out-credentials", "creds.json"); err == nil {
		t.Fatalf("expected write creds error")
	}

	// Write out-key failure
	env.app.OSWriteFile = func(filename string, data []byte, perm os.FileMode) error {
		if filename == "key.pem" {
			return errors.New("write key failed")
		}
		return nil
	}
	if err := executeCommand(env.app, "generate", sa, "--out-key", "key.pem"); err == nil {
		t.Fatalf("expected write key error")
	}

	// Write out-cert failure
	env.app.OSWriteFile = func(filename string, data []byte, perm os.FileMode) error {
		if filename == "cert.pem" {
			return errors.New("write cert failed")
		}
		return nil
	}
	if err := executeCommand(env.app, "generate", sa, "--out-cert", "cert.pem"); err == nil {
		t.Fatalf("expected write cert error")
	}
}

func TestUploadCommand(t *testing.T) {
	env := newTestEnv()
	sa := "sa@proj.iam.gserviceaccount.com"

	// Missing args
	if err := executeCommand(env.app, "upload"); err == nil {
		t.Fatalf("expected error for missing args")
	}

	// Empty email / file path
	if err := executeCommand(env.app, "upload", "  ", "cert.pem"); err == nil {
		t.Fatalf("expected error for empty email")
	}
	if err := executeCommand(env.app, "upload", sa, "  "); err == nil {
		t.Fatalf("expected error for empty file path")
	}

	// File read error
	if err := executeCommand(env.app, "upload", sa, "nonexistent.pem"); err == nil {
		t.Fatalf("expected file read error")
	}

	// Invalid max validity
	env.files["any.txt"] = []byte("content")
	if err := executeCommand(env.app, "upload", sa, "any.txt", "--max-validity", "invalid"); err == nil {
		t.Fatalf("expected error for invalid max-validity")
	}

	// File neither cert nor public key
	if err := executeCommand(env.app, "upload", sa, "any.txt"); err == nil {
		t.Fatalf("expected error for neither cert nor public key")
	}

	// Create valid X.509 cert
	priv, _ := crypto.GenerateRSAKeyPair(2048)
	certPEM, _ := crypto.CreateSelfSignedCertificate(priv, 24*time.Hour, "test")
	env.files["valid.crt"] = certPEM

	// Certificate validation failure (exceeds max validity)
	if err := executeCommand(env.app, "upload", sa, "valid.crt", "--max-validity", "5h"); err == nil {
		t.Fatalf("expected error when cert exceeds max validity")
	}

	// ClientFactory failure
	env.app.ClientFactory = func(ctx context.Context, credentialsFile string) (client.IAMClient, error) {
		return nil, errors.New("client init failed")
	}
	if err := executeCommand(env.app, "upload", sa, "valid.crt"); err == nil {
		t.Fatalf("expected client factory error")
	}
	env.app.ClientFactory = func(ctx context.Context, credentialsFile string) (client.IAMClient, error) {
		return env.mockClient, nil
	}

	// UploadKey failure
	env.mockClient.UploadKeyErr = errors.New("upload failed")
	if err := executeCommand(env.app, "upload", sa, "valid.crt"); err == nil {
		t.Fatalf("expected UploadKey error")
	}
	env.mockClient.UploadKeyErr = nil

	// Successful upload of valid certificate
	if err := executeCommand(env.app, "upload", sa, "valid.crt"); err != nil {
		t.Fatalf("unexpected valid cert upload error: %v", err)
	}

	// Create raw RSA public key file (e.g. from an HSM)
	pubDER, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	env.files["pub.pem"] = pubPEM

	// Raw RSA public key without --wrap-rsa should fail with helpful message
	if err := executeCommand(env.app, "upload", sa, "pub.pem"); err == nil || !strings.Contains(err.Error(), "--wrap-rsa") {
		t.Fatalf("expected helpful --wrap-rsa error, got: %v", err)
	}

	// Raw RSA public key with invalid --wrap-validity
	if err := executeCommand(env.app, "upload", sa, "pub.pem", "--wrap-rsa", "--wrap-validity", "invalid"); err == nil {
		t.Fatalf("expected error for invalid wrap-validity")
	}

	// Successful upload of raw RSA public key with --wrap-rsa
	if err := executeCommand(env.app, "upload", sa, "pub.pem", "--wrap-rsa", "--wrap-validity", "720h"); err != nil {
		t.Fatalf("unexpected wrap-rsa upload error: %v", err)
	}
}

func TestDeleteDisableEnableCommands(t *testing.T) {
	env := newTestEnv()
	sa := "sa@proj.iam.gserviceaccount.com"
	keyID := "key-123"

	// Missing args
	if err := executeCommand(env.app, "delete"); err == nil {
		t.Fatalf("expected delete missing args error")
	}
	if err := executeCommand(env.app, "disable"); err == nil {
		t.Fatalf("expected disable missing args error")
	}
	if err := executeCommand(env.app, "enable"); err == nil {
		t.Fatalf("expected enable missing args error")
	}

	// Empty email / keyID
	if err := executeCommand(env.app, "delete", "  ", keyID); err == nil {
		t.Fatalf("expected delete empty email error")
	}
	if err := executeCommand(env.app, "delete", sa, "  "); err == nil {
		t.Fatalf("expected delete empty keyID error")
	}
	if err := executeCommand(env.app, "disable", "  ", keyID); err == nil {
		t.Fatalf("expected disable empty email error")
	}
	if err := executeCommand(env.app, "disable", sa, "  "); err == nil {
		t.Fatalf("expected disable empty keyID error")
	}
	if err := executeCommand(env.app, "enable", "  ", keyID); err == nil {
		t.Fatalf("expected enable empty email error")
	}
	if err := executeCommand(env.app, "enable", sa, "  "); err == nil {
		t.Fatalf("expected enable empty keyID error")
	}

	// ClientFactory failure
	env.app.ClientFactory = func(ctx context.Context, credentialsFile string) (client.IAMClient, error) {
		return nil, errors.New("client init failed")
	}
	if err := executeCommand(env.app, "delete", sa, keyID); err == nil {
		t.Fatalf("expected delete client factory error")
	}
	if err := executeCommand(env.app, "disable", sa, keyID); err == nil {
		t.Fatalf("expected disable client factory error")
	}
	if err := executeCommand(env.app, "enable", sa, keyID); err == nil {
		t.Fatalf("expected enable client factory error")
	}
	env.app.ClientFactory = func(ctx context.Context, credentialsFile string) (client.IAMClient, error) {
		return env.mockClient, nil
	}

	// Operations on nonexistent key (mock returns not found)
	if err := executeCommand(env.app, "delete", sa, keyID); err == nil {
		t.Fatalf("expected delete not found error")
	}
	if err := executeCommand(env.app, "disable", sa, keyID); err == nil {
		t.Fatalf("expected disable not found error")
	}
	if err := executeCommand(env.app, "enable", sa, keyID); err == nil {
		t.Fatalf("expected enable not found error")
	}

	// Add key to mock
	env.mockClient.AddKey(sa, &client.KeyInfo{ID: keyID})

	// Successful disable
	if err := executeCommand(env.app, "disable", sa, keyID); err != nil {
		t.Fatalf("unexpected disable error: %v", err)
	}

	// Successful enable
	if err := executeCommand(env.app, "enable", sa, keyID); err != nil {
		t.Fatalf("unexpected enable error: %v", err)
	}

	// Successful delete
	if err := executeCommand(env.app, "delete", sa, keyID); err != nil {
		t.Fatalf("unexpected delete error: %v", err)
	}
}

func TestRotateCommand(t *testing.T) {
	env := newTestEnv()
	sa := "sa@proj.iam.gserviceaccount.com"

	// Missing arg
	if err := executeCommand(env.app, "rotate"); err == nil {
		t.Fatalf("expected rotate missing arg error")
	}

	// Empty email
	if err := executeCommand(env.app, "rotate", "  "); err == nil {
		t.Fatalf("expected rotate empty email error")
	}

	// Conflicting flags
	if err := executeCommand(env.app, "rotate", sa, "--disable-old", "--delete-old"); err == nil {
		t.Fatalf("expected error for both --disable-old and --delete-old")
	}

	// ClientFactory failure
	env.app.ClientFactory = func(ctx context.Context, credentialsFile string) (client.IAMClient, error) {
		return nil, errors.New("client init failed")
	}
	if err := executeCommand(env.app, "rotate", sa); err == nil {
		t.Fatalf("expected client factory error")
	}
	env.app.ClientFactory = func(ctx context.Context, credentialsFile string) (client.IAMClient, error) {
		return env.mockClient, nil
	}

	// ListKeys failure
	env.mockClient.ListKeysErr = errors.New("list failed")
	if err := executeCommand(env.app, "rotate", sa); err == nil {
		t.Fatalf("expected list keys failure")
	}
	env.mockClient.ListKeysErr = nil

	// Unsupported method
	if err := executeCommand(env.app, "rotate", sa, "--method", "unknown"); err == nil {
		t.Fatalf("expected error for unsupported method")
	}

	// Method local - invalid validity
	if err := executeCommand(env.app, "rotate", sa, "--method", "local", "--validity", "invalid"); err == nil {
		t.Fatalf("expected error for invalid validity")
	}

	// Method local - invalid bits
	if err := executeCommand(env.app, "rotate", sa, "--method", "local", "--bits", "512"); err == nil {
		t.Fatalf("expected error for invalid bits")
	}

	// Method local - 1024 bits with warning
	env.stderr.Reset()
	if err := executeCommand(env.app, "rotate", sa, "--method", "local", "--bits", "1024", "--out-credentials", "-"); err != nil {
		t.Fatalf("unexpected error for 1024 bits on rotate: %v", err)
	}
	if !strings.Contains(env.stderr.String(), "WARNING: 1024-bit RSA keys are deprecated") {
		t.Fatalf("expected warning for 1024 bits in stderr: %s", env.stderr.String())
	}

	// Method local - UploadKey failure
	env.mockClient.UploadKeyErr = errors.New("upload failed")
	if err := executeCommand(env.app, "rotate", sa, "--method", "local"); err == nil {
		t.Fatalf("expected upload failure")
	}
	env.mockClient.UploadKeyErr = nil

	// Method gcp - CreateKey failure
	env.mockClient.CreateKeyErr = errors.New("create failed")
	if err := executeCommand(env.app, "rotate", sa, "--method", "gcp"); err == nil {
		t.Fatalf("expected create failure")
	}
	env.mockClient.CreateKeyErr = nil

	// Save credentials file error
	env.app.OSWriteFile = func(filename string, data []byte, perm os.FileMode) error {
		return errors.New("write failed")
	}
	if err := executeCommand(env.app, "rotate", sa, "--method", "gcp", "--out-credentials", "creds.json"); err == nil {
		t.Fatalf("expected save credentials error")
	}
	env.app.OSWriteFile = func(filename string, data []byte, perm os.FileMode) error {
		env.files[filename] = data
		return nil
	}

	// Add an existing active key
	now := time.Now()
	env.mockClient.AddKey(sa, &client.KeyInfo{
		ID:              "old-active-key",
		KeyType:         client.KeyTypeUserManaged,
		Disabled:        false,
		ValidBeforeTime: now.Add(24 * time.Hour),
	})

	// Delete old key error
	env.mockClient.DeleteKeyErr = errors.New("delete failed")
	if err := executeCommand(env.app, "rotate", sa, "--delete-old"); err == nil {
		t.Fatalf("expected delete old key error")
	}
	env.mockClient.DeleteKeyErr = nil

	// Disable old key error
	env.mockClient.DisableKeyErr = errors.New("disable failed")
	if err := executeCommand(env.app, "rotate", sa, "--disable-old"); err == nil {
		t.Fatalf("expected disable old key error")
	}
	env.mockClient.DisableKeyErr = nil

	// Success with local method and stdout (-)
	env.stdout.Reset()
	if err := executeCommand(env.app, "rotate", sa, "--method", "local", "--out-credentials", "-"); err != nil {
		t.Fatalf("unexpected rotate local stdout error: %v", err)
	}

	// Success with gcp method and --delete-old
	if err := executeCommand(env.app, "rotate", sa, "--method", "gcp", "--delete-old"); err != nil {
		t.Fatalf("unexpected rotate gcp delete-old error: %v", err)
	}

	// Re-add active key and test --disable-old with JSON format
	env.mockClient.AddKey(sa, &client.KeyInfo{
		ID:              "old-active-2",
		KeyType:         client.KeyTypeUserManaged,
		Disabled:        false,
		ValidBeforeTime: now.Add(24 * time.Hour),
	})
	env.stdout.Reset()
	if err := executeCommand(env.app, "rotate", sa, "--disable-old", "--format", "json"); err != nil {
		t.Fatalf("unexpected rotate disable-old json error: %v", err)
	}
	if !strings.Contains(env.stdout.String(), "old-active-2") {
		t.Fatalf("expected old-active-2 in json output")
	}

	// Re-add active key and test --keep-old (default) with YAML format
	env.mockClient.AddKey(sa, &client.KeyInfo{
		ID:              "old-active-3",
		KeyType:         client.KeyTypeUserManaged,
		Disabled:        false,
		ValidBeforeTime: now.Add(24 * time.Hour),
	})
	env.stdout.Reset()
	if err := executeCommand(env.app, "rotate", sa, "--format", "yaml"); err != nil {
		t.Fatalf("unexpected rotate keep-old yaml error: %v", err)
	}
	if !strings.Contains(env.stdout.String(), "old-active-3") {
		t.Fatalf("expected old-active-3 in yaml output")
	}
}

func TestVersionCommand(t *testing.T) {
	env := newTestEnv()

	// Default text format
	env.stdout.Reset()
	if err := executeCommand(env.app, "version"); err != nil {
		t.Fatalf("unexpected version error: %v", err)
	}
	if !strings.Contains(env.stdout.String(), "version") {
		t.Fatalf("expected version in output: %s", env.stdout.String())
	}

	// JSON format
	env.stdout.Reset()
	if err := executeCommand(env.app, "version", "--format", "json"); err != nil {
		t.Fatalf("unexpected version json error: %v", err)
	}
	if !strings.Contains(env.stdout.String(), `"version":`) {
		t.Fatalf("expected JSON version in output: %s", env.stdout.String())
	}

	// YAML format
	env.stdout.Reset()
	if err := executeCommand(env.app, "version", "--format", "yaml"); err != nil {
		t.Fatalf("unexpected version yaml error: %v", err)
	}
	if !strings.Contains(env.stdout.String(), "version:") {
		t.Fatalf("expected YAML version in output: %s", env.stdout.String())
	}
}

type failWriter struct{}

func (failWriter) Write(p []byte) (n int, err error) {
	return 0, errors.New("write failure")
}

func TestGenerateCommand_CryptoErrors(t *testing.T) {
	sa := "sa@proj.iam.gserviceaccount.com"

	// CreateSelfSignedCertificate error
	env := newTestEnv()
	env.app.Crypto.CreateSelfSignedCertificate = func(priv *rsa.PrivateKey, validity time.Duration, commonName string) ([]byte, error) {
		return nil, errors.New("simulated cert error")
	}
	if err := executeCommand(env.app, "generate", sa); err == nil {
		t.Fatalf("expected error from CreateSelfSignedCertificate")
	}

	// EncodePrivateKeyToPKCS8PEM error
	env = newTestEnv()
	env.app.Crypto.EncodePrivateKeyToPKCS8PEM = func(priv *rsa.PrivateKey) ([]byte, error) {
		return nil, errors.New("simulated pem error")
	}
	if err := executeCommand(env.app, "generate", sa); err == nil {
		t.Fatalf("expected error from EncodePrivateKeyToPKCS8PEM")
	}

	// BuildGCPCredentialsJSON error
	env = newTestEnv()
	env.app.Crypto.BuildGCPCredentialsJSON = func(projectID, keyID, clientEmail string, privateKeyPEM []byte) ([]byte, error) {
		return nil, errors.New("simulated json error")
	}
	if err := executeCommand(env.app, "generate", sa); err == nil {
		t.Fatalf("expected error from BuildGCPCredentialsJSON")
	}
}

func TestUploadCommand_CryptoErrors(t *testing.T) {
	env := newTestEnv()
	sa := "sa@proj.iam.gserviceaccount.com"

	priv, _ := crypto.GenerateRSAKeyPair(2048)
	pubDER, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	env.files["pub.pem"] = pubPEM

	// Ephemeral key generation failure
	env.app.Crypto.GenerateRSAKeyPair = func(bits int) (*rsa.PrivateKey, error) {
		return nil, errors.New("simulated rsa gen error")
	}
	if err := executeCommand(env.app, "upload", sa, "pub.pem", "--wrap-rsa"); err == nil {
		t.Fatalf("expected error from GenerateRSAKeyPair during wrap")
	}

	// WrapRSAPublicKeyInCert error
	env.app.Crypto.GenerateRSAKeyPair = crypto.GenerateRSAKeyPair
	env.app.Crypto.WrapRSAPublicKeyInCert = func(pub *rsa.PublicKey, signer cryptopkg.Signer, validity time.Duration, commonName string) ([]byte, error) {
		return nil, errors.New("simulated wrap error")
	}
	if err := executeCommand(env.app, "upload", sa, "pub.pem", "--wrap-rsa"); err == nil {
		t.Fatalf("expected error from WrapRSAPublicKeyInCert")
	}
}

func TestRotateCommand_CryptoErrorsAndBranches(t *testing.T) {
	sa := "sa@proj.iam.gserviceaccount.com"

	// CreateSelfSignedCertificate error in rotate
	env := newTestEnv()
	env.app.Crypto.CreateSelfSignedCertificate = func(priv *rsa.PrivateKey, validity time.Duration, commonName string) ([]byte, error) {
		return nil, errors.New("simulated cert error")
	}
	if err := executeCommand(env.app, "rotate", sa, "--method", "local"); err == nil {
		t.Fatalf("expected error from CreateSelfSignedCertificate in rotate")
	}

	// EncodePrivateKeyToPKCS8PEM error in rotate
	env = newTestEnv()
	env.app.Crypto.EncodePrivateKeyToPKCS8PEM = func(priv *rsa.PrivateKey) ([]byte, error) {
		return nil, errors.New("simulated pem error")
	}
	if err := executeCommand(env.app, "rotate", sa, "--method", "local"); err == nil {
		t.Fatalf("expected error from EncodePrivateKeyToPKCS8PEM in rotate")
	}

	// BuildGCPCredentialsJSON error in rotate
	env = newTestEnv()
	env.app.Crypto.BuildGCPCredentialsJSON = func(projectID, keyID, clientEmail string, privateKeyPEM []byte) ([]byte, error) {
		return nil, errors.New("simulated json error")
	}
	if err := executeCommand(env.app, "rotate", sa, "--method", "local"); err == nil {
		t.Fatalf("expected error from BuildGCPCredentialsJSON in rotate")
	}

	// Stdout write error in rotate
	env = newTestEnv()
	env.app.Out = failWriter{}
	if err := executeCommand(env.app, "rotate", sa, "--method", "local", "--out-credentials", "-"); err == nil {
		t.Fatalf("expected stdout write error in rotate")
	}

	// Rotate with --disable-old using default table format (covers summary print)
	env = newTestEnv()
	now := time.Now()
	env.mockClient.AddKey(sa, &client.KeyInfo{
		ID:              "key-to-disable",
		KeyType:         client.KeyTypeUserManaged,
		Disabled:        false,
		ValidBeforeTime: now.Add(24 * time.Hour),
	})
	if err := executeCommand(env.app, "rotate", sa, "--disable-old"); err != nil {
		t.Fatalf("unexpected error with disable-old in default format: %v", err)
	}
	if !strings.Contains(env.stdout.String(), "Old Keys Disabled: key-to-disable") {
		t.Fatalf("expected 'Old Keys Disabled: key-to-disable' in output: %s", env.stdout.String())
	}
}

