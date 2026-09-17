package cmd

import (
	"fmt"
	"strings"

	"github.com/jay0lee/go-sa-key-manager/pkg/client"
	"github.com/jay0lee/go-sa-key-manager/pkg/output"
	"github.com/spf13/cobra"
)

func newListCmd(app *App) *cobra.Command {
	var keyTypeFilter string

	cmd := &cobra.Command{
		Use:   "list <service-account-email>",
		Short: "List keys for a service account",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			saEmail := strings.TrimSpace(args[0])
			if saEmail == "" {
				return fmt.Errorf("service account email cannot be empty")
			}

			var keyTypes []client.KeyType
			switch strings.ToLower(keyTypeFilter) {
			case "user":
				keyTypes = []client.KeyType{client.KeyTypeUserManaged}
			case "system":
				keyTypes = []client.KeyType{client.KeyTypeSystemManaged}
			case "all", "":
				keyTypes = []client.KeyType{client.KeyTypeUserManaged, client.KeyTypeSystemManaged}
			default:
				return fmt.Errorf("invalid key type filter %q (allowed: all, user, system)", keyTypeFilter)
			}

			iamClient, err := app.ClientFactory(cmd.Context(), app.CredentialsFile)
			if err != nil {
				return err
			}
			defer iamClient.Close()

			keys, err := iamClient.ListKeys(cmd.Context(), saEmail, keyTypes)
			if err != nil {
				return err
			}

			return output.FormatOutput(app.Out, app.Format, keys)
		},
	}

	cmd.Flags().StringVar(&keyTypeFilter, "type", "all", "Key type filter: all, user, system")
	return cmd
}
