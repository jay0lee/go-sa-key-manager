package cmd

import (
	"fmt"
	"strings"
	"time"

	"github.com/jay0lee/go-sa-key-manager/pkg/crypto"
	"github.com/spf13/cobra"
)

func newUploadCmd(app *App) *cobra.Command {
	var (
		checkValidity   bool
		maxValidityStr  string
		wrapRSA         bool
		wrapValidityStr string
		commonName      string
	)

	cmd := &cobra.Command{
		Use:   "upload <service-account-email> <public-key-or-cert-file>",
		Short: "Upload a pre-existing public key or X.509 certificate (such as from an HSM)",
		Long: `Uploads the public key material for a service account. This allows you to use keys
generated inside an HSM (Hardware Security Module), TPM, or external key store where
the private key never leaves the secure hardware module.

Google Cloud IAM requires public keys to be in the form of an RSA public key wrapped in an
X.509 v3 certificate. If your HSM exports only a raw RSA public key, use --wrap-rsa to
automatically wrap the public key into an X.509 certificate.`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			saEmail := strings.TrimSpace(args[0])
			filePath := strings.TrimSpace(args[1])
			if saEmail == "" {
				return fmt.Errorf("service account email cannot be empty")
			}
			if filePath == "" {
				return fmt.Errorf("public key / certificate file path cannot be empty")
			}

			fileBytes, err := app.OSReadFile(filePath)
			if err != nil {
				return fmt.Errorf("failed to read file %q: %w", filePath, err)
			}

			var maxValidity time.Duration
			if maxValidityStr != "" {
				mv, err := parseValidityDuration(maxValidityStr, 0, 0)
				if err != nil {
					return fmt.Errorf("invalid --max-validity: %w", err)
				}
				maxValidity = mv
			}

			var uploadBytes []byte

			// 1. Try parsing as X.509 certificate
			cert, certErr := crypto.ParseCertificate(fileBytes)
			if certErr == nil {
				if checkValidity {
					if err := crypto.ValidateCertValidity(cert, maxValidity); err != nil {
						return fmt.Errorf("certificate validation failed: %w", err)
					}
				}
				uploadBytes = fileBytes
			} else {
				// 2. Try parsing as raw RSA public key
				pubKey, pubErr := crypto.ParseRSAPublicKey(fileBytes)
				if pubErr != nil {
					return fmt.Errorf("file is neither a valid X.509 certificate (%v) nor an RSA public key (%v)", certErr, pubErr)
				}

				if !wrapRSA {
					return fmt.Errorf("the provided file contains an RSA public key, but GCP IAM requires an X.509 v3 certificate wrapper.\nRun again with '--wrap-rsa' to automatically wrap your HSM/public key in a certificate")
				}

				wrapValidity, err := parseValidityDuration(wrapValidityStr, 0, 0)
				if err != nil {
					return fmt.Errorf("invalid --wrap-validity: %w", err)
				}

				// Generate ephemeral signer to sign the wrapper certificate
				ephemeralSigner, err := app.Crypto.GenerateRSAKeyPair(2048)
				if err != nil {
					return fmt.Errorf("failed to generate ephemeral signer for public key wrapping: %w", err)
				}

				wrappedCert, err := app.Crypto.WrapRSAPublicKeyInCert(pubKey, ephemeralSigner, wrapValidity, commonName)
				if err != nil {
					return fmt.Errorf("failed to wrap RSA public key in certificate: %w", err)
				}

				uploadBytes = wrappedCert
			}

			iamClient, err := app.ClientFactory(cmd.Context(), app.CredentialsFile)
			if err != nil {
				return err
			}
			defer iamClient.Close()

			keyInfo, err := iamClient.UploadKey(cmd.Context(), saEmail, uploadBytes)
			if err != nil {
				return err
			}

			if err := app.VerifyKeyReady(cmd.Context(), iamClient, saEmail, keyInfo.ID); err != nil {
				return fmt.Errorf("key uploaded but failed readiness verification: %w", err)
			}

			fmt.Fprintf(app.Out, "Successfully uploaded public key to service account %s:\n", saEmail)
			fmt.Fprintf(app.Out, "  Key ID:       %s\n", keyInfo.ID)
			fmt.Fprintf(app.Out, "  Resource:     %s\n", keyInfo.Name)
			fmt.Fprintf(app.Out, "  Valid From:   %s\n", keyInfo.ValidAfterTime.Format(time.RFC3339))
			fmt.Fprintf(app.Out, "  Valid Before: %s\n", keyInfo.ValidBeforeTime.Format(time.RFC3339))

			return nil
		},
	}

	cmd.Flags().BoolVar(&checkValidity, "check-validity", true, "Validate that certificate has not expired before uploading")
	cmd.Flags().StringVar(&maxValidityStr, "max-validity", "", "Maximum allowed certificate validity duration for policy check (e.g. '2160h')")
	cmd.Flags().BoolVar(&wrapRSA, "wrap-rsa", false, "Wrap a raw RSA public key (e.g. from an HSM) into an X.509 certificate before upload")
	cmd.Flags().StringVar(&wrapValidityStr, "wrap-validity", "2160h", "Validity duration if wrapping an RSA public key")
	cmd.Flags().StringVar(&commonName, "common-name", "service-account-key", "Common Name for X.509 certificate subject if wrapping")

	return cmd
}
