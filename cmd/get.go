package cmd

import (
	"fmt"
	"strings"

	"github.com/jay0lee/go-sa-key-manager/pkg/output"
	"github.com/spf13/cobra"
)

func newGetCmd(app *App) *cobra.Command {
	var (
		showPublicKey bool
		outFile       string
	)

	cmd := &cobra.Command{
		Use:   "get <service-account-email> <key-id>",
		Short: "Get metadata or public key for a specific service account key",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			saEmail := strings.TrimSpace(args[0])
			keyID := strings.TrimSpace(args[1])
			if saEmail == "" {
				return fmt.Errorf("service account email cannot be empty")
			}
			if keyID == "" {
				return fmt.Errorf("key ID cannot be empty")
			}

			iamClient, err := app.ClientFactory(cmd.Context(), app.CredentialsFile)
			if err != nil {
				return err
			}
			defer iamClient.Close()

			key, err := iamClient.GetKey(cmd.Context(), saEmail, keyID)
			if err != nil {
				return err
			}

			if showPublicKey {
				if len(key.PublicKeyData) == 0 {
					return fmt.Errorf("key %s does not contain public key data", keyID)
				}
				if outFile != "" {
					if err := app.OSWriteFile(outFile, key.PublicKeyData, 0600); err != nil {
						return fmt.Errorf("failed to write public key to %q: %w", outFile, err)
					}
					fmt.Fprintf(app.Out, "Public key successfully saved to %s\n", outFile)
					return nil
				}
				_, err := app.Out.Write(key.PublicKeyData)
				return err
			}

			return output.FormatOutput(app.Out, app.Format, key)
		},
	}

	cmd.Flags().BoolVar(&showPublicKey, "public-key", false, "Output public key data instead of metadata")
	cmd.Flags().StringVarP(&outFile, "out", "o", "", "Output file path when --public-key is specified")

	return cmd
}
