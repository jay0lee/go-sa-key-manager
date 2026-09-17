package cmd

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

func newEnableCmd(app *App) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "enable <service-account-email> <key-id>",
		Short: "Enable a disabled service account key",
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

			if err := iamClient.EnableKey(cmd.Context(), saEmail, keyID); err != nil {
				return err
			}

			fmt.Fprintf(app.Out, "Successfully enabled key %s for service account %s\n", keyID, saEmail)
			return nil
		},
	}

	return cmd
}
