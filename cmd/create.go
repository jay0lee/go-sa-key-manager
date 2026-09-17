package cmd

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

func newCreateCmd(app *App) *cobra.Command {
	var outFile string

	cmd := &cobra.Command{
		Use:   "create <service-account-email>",
		Short: "Create a GCP-managed service account key pair and save private key credentials",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			saEmail := strings.TrimSpace(args[0])
			if saEmail == "" {
				return fmt.Errorf("service account email cannot be empty")
			}

			iamClient, err := app.ClientFactory(cmd.Context(), app.CredentialsFile)
			if err != nil {
				return err
			}
			defer iamClient.Close()

			key, err := iamClient.CreateKey(cmd.Context(), saEmail)
			if err != nil {
				return err
			}

			if len(key.PrivateKeyData) == 0 {
				return fmt.Errorf("GCP response did not include private key data")
			}

			targetFile := outFile
			if targetFile == "" {
				targetFile = fmt.Sprintf("%s-%s.json", saEmail, key.ID)
			}

			if targetFile == "-" {
				if _, err := app.Out.Write(key.PrivateKeyData); err != nil {
					return err
				}
			} else {
				if err := app.OSWriteFile(targetFile, key.PrivateKeyData, 0600); err != nil {
					return fmt.Errorf("failed to save private key credentials to %q: %w", targetFile, err)
				}
			}

			if err := app.VerifyKeyReady(cmd.Context(), iamClient, saEmail, key.ID); err != nil {
				return fmt.Errorf("key created but failed readiness verification: %w", err)
			}

			fmt.Fprintf(app.Out, "Successfully created GCP-managed key: %s\nSaved credentials to: %s\n", key.ID, targetFile)
			return nil
		},
	}

	cmd.Flags().StringVarP(&outFile, "out", "o", "", "File path to save credentials JSON (default: <sa>-<key-id>.json, use '-' for stdout)")
	return cmd
}
