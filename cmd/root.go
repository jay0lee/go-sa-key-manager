package cmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	cryptopkg "crypto"
	"crypto/rsa"

	"github.com/jay0lee/go-sa-key-manager/pkg/client"
	"github.com/jay0lee/go-sa-key-manager/pkg/crypto"
	"github.com/spf13/cobra"
)

// CryptoOps encapsulates cryptographic operations for testability.
type CryptoOps struct {
	GenerateRSAKeyPair          func(bits int) (*rsa.PrivateKey, error)
	CreateSelfSignedCertificate func(priv *rsa.PrivateKey, validity time.Duration, commonName string) ([]byte, error)
	EncodePrivateKeyToPKCS8PEM  func(priv *rsa.PrivateKey) ([]byte, error)
	BuildGCPCredentialsJSON     func(projectID, keyID, clientEmail string, privateKeyPEM []byte) ([]byte, error)
	WrapRSAPublicKeyInCert      func(pub *rsa.PublicKey, signer cryptopkg.Signer, validity time.Duration, commonName string) ([]byte, error)
}

// KeyReadinessVerifier verifies a key is both queryable via IAM and published publicly.
type KeyReadinessVerifier func(ctx context.Context, iamClient client.IAMClient, saEmail, keyID string) error

// App encapsulates dependencies for the CLI application.
type App struct {
	In             io.Reader
	Out            io.Writer
	ErrOut         io.Writer
	ClientFactory  func(ctx context.Context, credentialsFile string) (client.IAMClient, error)
	VerifyKeyReady KeyReadinessVerifier
	OSWriteFile    func(filename string, data []byte, perm os.FileMode) error
	OSReadFile     func(filename string) ([]byte, error)
	Crypto         CryptoOps

	// Global flag values
	Format          string
	CredentialsFile string
	Verbose         bool
}

// NewDefaultApp creates an App with standard OS and GCP dependencies.
func NewDefaultApp() *App {
	return &App{
		In:     os.Stdin,
		Out:    os.Stdout,
		ErrOut: os.Stderr,
		ClientFactory: func(ctx context.Context, credentialsFile string) (client.IAMClient, error) {
			return client.NewGCPClient(ctx, client.GCPClientOptions{
				CredentialsFile: credentialsFile,
			})
		},
		VerifyKeyReady: func(ctx context.Context, iamClient client.IAMClient, saEmail, keyID string) error {
			return client.WaitForKeyFullyPropagated(ctx, iamClient, saEmail, keyID, 45*time.Second)
		},
		OSWriteFile: os.WriteFile,
		OSReadFile:  os.ReadFile,
		Crypto: CryptoOps{
			GenerateRSAKeyPair:          crypto.GenerateRSAKeyPair,
			CreateSelfSignedCertificate: crypto.CreateSelfSignedCertificate,
			EncodePrivateKeyToPKCS8PEM:  crypto.EncodePrivateKeyToPKCS8PEM,
			BuildGCPCredentialsJSON:     crypto.BuildGCPCredentialsJSON,
			WrapRSAPublicKeyInCert:      crypto.WrapRSAPublicKeyInCert,
		},
		Format: "table",
	}
}

// NewRootCommand builds the root cobra command and attaches all subcommands.
func NewRootCommand(app *App) *cobra.Command {
	if app == nil {
		app = NewDefaultApp()
	}

	rootCmd := &cobra.Command{
		Use:   "gcp-sa-key-manager",
		Short: "A cross-platform CLI for GCP Service Account key lifecycle and rotation",
		Long: `gcp-sa-key-manager is a high-security, zero-dependency CLI for managing Google Cloud Platform
Service Account keys, generating local RSA keys, uploading HSM public keys, and automating key rotation
while adhering to GCP Organization Policies (iam.disableServiceAccountKeyCreation, iam.serviceAccountKeyExpiryHours).`,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			cmd.SilenceUsage = true
		},
	}

	rootCmd.SetIn(app.In)
	rootCmd.SetOut(app.Out)
	rootCmd.SetErr(app.ErrOut)

	rootCmd.PersistentFlags().StringVarP(&app.Format, "format", "f", "table", "Output format: table, json, yaml")
	rootCmd.PersistentFlags().StringVarP(&app.CredentialsFile, "credentials-file", "c", "", "Path to explicit GCP credentials JSON (defaults to ADC)")
	rootCmd.PersistentFlags().BoolVarP(&app.Verbose, "verbose", "v", false, "Enable verbose logging")

	rootCmd.AddCommand(
		newListCmd(app),
		newGetCmd(app),
		newCreateCmd(app),
		newGenerateCmd(app),
		newUploadCmd(app),
		newDeleteCmd(app),
		newDisableCmd(app),
		newEnableCmd(app),
		newRotateCmd(app),
		newVersionCmd(app),
	)

	return rootCmd
}

// parseValidityDuration resolves validity duration from hours, days, or duration string.
func parseValidityDuration(durStr string, days, hours int) (time.Duration, error) {
	if hours > 0 {
		return time.Duration(hours) * time.Hour, nil
	}
	if days > 0 {
		return time.Duration(days) * 24 * time.Hour, nil
	}
	if durStr == "" {
		return 2160 * time.Hour, nil // default 90 days
	}

	// Support day format like "30d" or "90d"
	if strings.HasSuffix(durStr, "d") {
		var d int
		if _, err := fmt.Sscanf(durStr, "%dd", &d); err == nil && d > 0 {
			return time.Duration(d) * 24 * time.Hour, nil
		}
	}

	dur, err := time.ParseDuration(durStr)
	if err != nil {
		return 0, fmt.Errorf("invalid validity duration %q: %w (expected format e.g. '24h', '30d', '2160h')", durStr, err)
	}
	if dur <= 0 {
		return 0, fmt.Errorf("validity duration must be greater than zero, got %v", dur)
	}
	return dur, nil
}
