package cmd

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

func newGenerateCmd(app *App) *cobra.Command {
	var (
		bits           int
		validityStr    string
		validityDays   int
		validityHours  int
		outCredentials string
		outKey         string
		outCert        string
		commonName     string
	)

	cmd := &cobra.Command{
		Use:   "generate <service-account-email>",
		Short: "Generate an RSA key pair locally, upload the public certificate to GCP, and output credentials JSON",
		Long: `Generates a new RSA private key locally on this machine so the private key material never leaves
your environment. A self-signed X.509 certificate wrapping the public key is generated and uploaded
to GCP IAM. A ready-to-use GCP Service Account credentials JSON file is generated for client authentication.

Use --validity, --validity-days, or --validity-hours to configure key lifespan to comply with
GCP organization policy constraints (e.g. constraints/iam.serviceAccountKeyExpiryHours).`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			saEmail := strings.TrimSpace(args[0])
			if saEmail == "" {
				return fmt.Errorf("service account email cannot be empty")
			}

			validity, err := parseValidityDuration(validityStr, validityDays, validityHours)
			if err != nil {
				return err
			}

			if bits == 1024 {
				fmt.Fprintln(app.ErrOut, "WARNING: 1024-bit RSA keys are deprecated and considered cryptographically insecure. A minimum of 2048 bits is strongly recommended.")
			}

			privKey, err := app.Crypto.GenerateRSAKeyPair(bits)
			if err != nil {
				return err
			}

			certPEM, err := app.Crypto.CreateSelfSignedCertificate(privKey, validity, commonName)
			if err != nil {
				return err
			}

			iamClient, err := app.ClientFactory(cmd.Context(), app.CredentialsFile)
			if err != nil {
				return err
			}
			defer iamClient.Close()

			keyInfo, err := iamClient.UploadKey(cmd.Context(), saEmail, certPEM)
			if err != nil {
				return err
			}

			privKeyPEM, err := app.Crypto.EncodePrivateKeyToPKCS8PEM(privKey)
			if err != nil {
				return err
			}

			credsJSON, err := app.Crypto.BuildGCPCredentialsJSON("", keyInfo.ID, saEmail, privKeyPEM)
			if err != nil {
				return err
			}

			targetCreds := outCredentials
			if targetCreds == "" {
				targetCreds = fmt.Sprintf("%s-%s.json", saEmail, keyInfo.ID)
			}

			if targetCreds == "-" {
				_, err := app.Out.Write(credsJSON)
				return err
			}

			if err := app.OSWriteFile(targetCreds, credsJSON, 0600); err != nil {
				return fmt.Errorf("failed to save credentials JSON to %q: %w", targetCreds, err)
			}

			if outKey != "" {
				if err := app.OSWriteFile(outKey, privKeyPEM, 0600); err != nil {
					return fmt.Errorf("failed to save private key PEM to %q: %w", outKey, err)
				}
			}

			if outCert != "" {
				if err := app.OSWriteFile(outCert, certPEM, 0644); err != nil {
					return fmt.Errorf("failed to save certificate PEM to %q: %w", outCert, err)
				}
			}

			if err := app.VerifyKeyReady(cmd.Context(), iamClient, saEmail, keyInfo.ID); err != nil {
				return fmt.Errorf("key generated and uploaded but failed readiness verification: %w", err)
			}

			fmt.Fprintf(app.Out, "Successfully generated local RSA key and uploaded to GCP:\n")
			fmt.Fprintf(app.Out, "  Key ID:          %s\n", keyInfo.ID)
			fmt.Fprintf(app.Out, "  Validity:        %v\n", validity)
			fmt.Fprintf(app.Out, "  Credentials File: %s\n", targetCreds)
			if outKey != "" {
				fmt.Fprintf(app.Out, "  Private Key File: %s\n", outKey)
			}
			if outCert != "" {
				fmt.Fprintf(app.Out, "  Certificate File: %s\n", outCert)
			}

			return nil
		},
	}

	cmd.Flags().IntVar(&bits, "bits", 2048, "RSA key size in bits (1024 [insecure], 2048, 3072, 4096)")
	cmd.Flags().StringVar(&validityStr, "validity", "2160h", "Key validity duration (e.g. 24h, 30d, 2160h)")
	cmd.Flags().IntVar(&validityDays, "validity-days", 0, "Key validity duration in days (overrides --validity)")
	cmd.Flags().IntVar(&validityHours, "validity-hours", 0, "Key validity duration in hours (overrides --validity)")
	cmd.Flags().StringVarP(&outCredentials, "out-credentials", "o", "", "Path to save credentials JSON (default: <sa>-<key-id>.json, use '-' for stdout)")
	cmd.Flags().StringVar(&outKey, "out-key", "", "Optional path to save private key PEM file")
	cmd.Flags().StringVar(&outCert, "out-cert", "", "Optional path to save public certificate PEM file")
	cmd.Flags().StringVar(&commonName, "common-name", "service-account-key", "Common Name for X.509 certificate subject")

	return cmd
}
