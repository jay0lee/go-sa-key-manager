package cmd

import (
	"fmt"
	"strings"
	"time"

	"github.com/jay0lee/go-sa-key-manager/pkg/client"
	"github.com/jay0lee/go-sa-key-manager/pkg/output"
	"github.com/spf13/cobra"
)

// RotationResult stores the outcome of a service account key rotation.
type RotationResult struct {
	ServiceAccount  string    `json:"service_account" yaml:"service_account"`
	NewKeyID        string    `json:"new_key_id" yaml:"new_key_id"`
	CredentialsFile string    `json:"credentials_file" yaml:"credentials_file"`
	Method          string    `json:"method" yaml:"method"`
	Timestamp       time.Time `json:"timestamp" yaml:"timestamp"`
	OldKeysDisabled []string  `json:"old_keys_disabled,omitempty" yaml:"old_keys_disabled,omitempty"`
	OldKeysDeleted  []string  `json:"old_keys_deleted,omitempty" yaml:"old_keys_deleted,omitempty"`
	OldKeysKept     []string  `json:"old_keys_kept,omitempty" yaml:"old_keys_kept,omitempty"`
}

func newRotateCmd(app *App) *cobra.Command {
	var (
		method         string
		bits           int
		validityStr    string
		validityDays   int
		validityHours  int
		outCredentials string
		disableOld     bool
		deleteOld      bool
		commonName     string
	)

	cmd := &cobra.Command{
		Use:   "rotate <service-account-email>",
		Short: "Rotate service account keys (create new, verify, and retire/disable old keys)",
		Long: `Executes a full key rotation workflow for a Google Cloud Service Account:
1. Identifies currently active user-managed keys.
2. Generates a new key pair (locally or GCP-managed) and saves new credentials.
3. Automatically transitions existing keys based on security policy:
   --disable-old disables previous keys immediately (safe rollback capability).
   --delete-old permanently deletes previous keys.
   Default keeps previous keys active to allow a transition grace period.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			saEmail := strings.TrimSpace(args[0])
			if saEmail == "" {
				return fmt.Errorf("service account email cannot be empty")
			}

			if disableOld && deleteOld {
				return fmt.Errorf("cannot specify both --disable-old and --delete-old")
			}

			iamClient, err := app.ClientFactory(cmd.Context(), app.CredentialsFile)
			if err != nil {
				return err
			}
			defer iamClient.Close()

			// 1. Fetch existing user-managed keys
			existingKeys, err := iamClient.ListKeys(cmd.Context(), saEmail, []client.KeyType{client.KeyTypeUserManaged})
			if err != nil {
				return err
			}

			var activeOldKeyIDs []string
			now := time.Now()
			for _, k := range existingKeys {
				if !k.Disabled && now.Before(k.ValidBeforeTime) {
					activeOldKeyIDs = append(activeOldKeyIDs, k.ID)
				}
			}

			// 2. Generate new key according to method
			var (
				newKeyID   string
				credsBytes []byte
			)

			switch strings.ToLower(method) {
			case "local":
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

				uploadedKey, err := iamClient.UploadKey(cmd.Context(), saEmail, certPEM)
				if err != nil {
					return err
				}
				newKeyID = uploadedKey.ID

				privKeyPEM, err := app.Crypto.EncodePrivateKeyToPKCS8PEM(privKey)
				if err != nil {
					return err
				}

				credsBytes, err = app.Crypto.BuildGCPCredentialsJSON("", newKeyID, saEmail, privKeyPEM)
				if err != nil {
					return err
				}

			case "gcp":
				gcpKey, err := iamClient.CreateKey(cmd.Context(), saEmail)
				if err != nil {
					return err
				}
				newKeyID = gcpKey.ID
				credsBytes = gcpKey.PrivateKeyData

			default:
				return fmt.Errorf("unsupported rotation method %q (allowed: local, gcp)", method)
			}

			// 3. Save new credentials
			targetCreds := outCredentials
			if targetCreds == "" {
				targetCreds = fmt.Sprintf("%s-rotated-%s.json", saEmail, newKeyID)
			}

			if targetCreds == "-" {
				if _, err := app.Out.Write(credsBytes); err != nil {
					return err
				}
			} else {
				if err := app.OSWriteFile(targetCreds, credsBytes, 0600); err != nil {
					return fmt.Errorf("failed to save rotated credentials to %q: %w", targetCreds, err)
				}
			}

			// 3.5. Verify new key is fully propagated before retiring old keys
			if err := app.VerifyKeyReady(cmd.Context(), iamClient, saEmail, newKeyID); err != nil {
				return fmt.Errorf("new key %s created but failed readiness verification (old keys left unchanged): %w", newKeyID, err)
			}

			// 4. Handle old keys
			result := RotationResult{
				ServiceAccount:  saEmail,
				NewKeyID:        newKeyID,
				CredentialsFile: targetCreds,
				Method:          method,
				Timestamp:       now,
			}

			if deleteOld {
				for _, oldID := range activeOldKeyIDs {
					if err := iamClient.DeleteKey(cmd.Context(), saEmail, oldID); err != nil {
						return fmt.Errorf("failed to delete old key %s during rotation: %w", oldID, err)
					}
					result.OldKeysDeleted = append(result.OldKeysDeleted, oldID)
				}
			} else if disableOld {
				for _, oldID := range activeOldKeyIDs {
					if err := iamClient.DisableKey(cmd.Context(), saEmail, oldID); err != nil {
						return fmt.Errorf("failed to disable old key %s during rotation: %w", oldID, err)
					}
					result.OldKeysDisabled = append(result.OldKeysDisabled, oldID)
				}
			} else {
				result.OldKeysKept = activeOldKeyIDs
			}

			// 5. Output results
			if app.Format == "json" {
				return output.PrintJSON(app.Out, result)
			}
			if app.Format == "yaml" {
				return output.PrintYAML(app.Out, result)
			}

			fmt.Fprintf(app.Out, "Key rotation completed successfully for %s\n", saEmail)
			fmt.Fprintf(app.Out, "  New Key ID:       %s\n", result.NewKeyID)
			fmt.Fprintf(app.Out, "  Method:           %s\n", result.Method)
			fmt.Fprintf(app.Out, "  Credentials File: %s\n", result.CredentialsFile)

			if len(result.OldKeysDisabled) > 0 {
				fmt.Fprintf(app.Out, "  Old Keys Disabled: %s\n", strings.Join(result.OldKeysDisabled, ", "))
			}
			if len(result.OldKeysDeleted) > 0 {
				fmt.Fprintf(app.Out, "  Old Keys Deleted:  %s\n", strings.Join(result.OldKeysDeleted, ", "))
			}
			if len(result.OldKeysKept) > 0 {
				fmt.Fprintf(app.Out, "  Old Keys Kept:     %s (transition grace period)\n", strings.Join(result.OldKeysKept, ", "))
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&method, "method", "local", "Rotation method: 'local' (generate RSA locally) or 'gcp' (GCP-managed)")
	cmd.Flags().IntVar(&bits, "bits", 2048, "RSA key size in bits (1024 [insecure], 2048, 3072, 4096)")
	cmd.Flags().StringVar(&validityStr, "validity", "2160h", "Key validity duration (for local method)")
	cmd.Flags().IntVar(&validityDays, "validity-days", 0, "Key validity duration in days (for local method)")
	cmd.Flags().IntVar(&validityHours, "validity-hours", 0, "Key validity duration in hours (for local method)")
	cmd.Flags().StringVarP(&outCredentials, "out-credentials", "o", "", "Path to save rotated credentials JSON (default: <sa>-rotated-<key-id>.json)")
	cmd.Flags().BoolVar(&disableOld, "disable-old", false, "Disable previously active user-managed keys")
	cmd.Flags().BoolVar(&deleteOld, "delete-old", false, "Permanently delete previously active user-managed keys")
	cmd.Flags().StringVar(&commonName, "common-name", "service-account-key", "Common name for certificate subject (local method)")

	return cmd
}
