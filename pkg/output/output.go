package output

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/jay0lee/go-sa-key-manager/pkg/client"
	"github.com/olekukonko/tablewriter"
	"gopkg.in/yaml.v3"
)

// FormatOutput prints data to w using the specified format ("table", "json", "yaml").
func FormatOutput(w io.Writer, format string, data any) error {
	switch format {
	case "table", "":
		return printTable(w, data)
	case "json":
		return PrintJSON(w, data)
	case "yaml":
		return PrintYAML(w, data)
	default:
		return fmt.Errorf("unsupported output format %q (allowed: table, json, yaml)", format)
	}
}

// PrintJSON writes indented JSON representation of data to w.
func PrintJSON(w io.Writer, data any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(data)
}

// PrintYAML writes YAML representation of data to w.
func PrintYAML(w io.Writer, data any) error {
	enc := yaml.NewEncoder(w)
	defer enc.Close()
	return enc.Encode(data)
}

func printTable(w io.Writer, data any) error {
	switch v := data.(type) {
	case []*client.KeyInfo:
		PrintKeysTable(w, v)
		return nil
	case *client.KeyInfo:
		PrintKeyDetailsTable(w, v)
		return nil
	default:
		// Fallback to JSON for custom data structures without a specialized table renderer
		return PrintJSON(w, data)
	}
}

// PrintKeysTable writes a table of service account keys to w.
func PrintKeysTable(w io.Writer, keys []*client.KeyInfo) {
	table := tablewriter.NewWriter(w)
	table.Header("KEY ID", "STATUS", "TYPE", "ALGORITHM", "VALID FROM", "EXPIRES", "REMAINING")

	for _, k := range keys {
		statusStr := "ACTIVE"
		if k.Disabled {
			statusStr = "DISABLED"
		} else if time.Now().After(k.ValidBeforeTime) {
			statusStr = "EXPIRED"
		}

		validFrom := k.ValidAfterTime.Format("2006-01-02 15:04:05")
		expires := k.ValidBeforeTime.Format("2006-01-02 15:04:05")
		remaining := CalculateRemainingValidity(k.ValidBeforeTime)

		_ = table.Append(
			k.ID,
			statusStr,
			string(k.KeyType),
			k.KeyAlgorithm,
			validFrom,
			expires,
			remaining,
		)
	}

	_ = table.Render()
}

// PrintKeyDetailsTable writes a key-value detail table for a single key to w.
func PrintKeyDetailsTable(w io.Writer, k *client.KeyInfo) {
	table := tablewriter.NewWriter(w)
	table.Header("FIELD", "VALUE")

	statusStr := "ACTIVE"
	if k.Disabled {
		statusStr = "DISABLED"
	} else if time.Now().After(k.ValidBeforeTime) {
		statusStr = "EXPIRED"
	}

	_ = table.Append("Key ID", k.ID)
	_ = table.Append("Resource Name", k.Name)
	_ = table.Append("Status", statusStr)
	_ = table.Append("Key Type", string(k.KeyType))
	_ = table.Append("Algorithm", k.KeyAlgorithm)
	_ = table.Append("Valid From", k.ValidAfterTime.Format(time.RFC3339))
	_ = table.Append("Expires", k.ValidBeforeTime.Format(time.RFC3339))
	_ = table.Append("Remaining", CalculateRemainingValidity(k.ValidBeforeTime))

	_ = table.Render()
}

// CalculateRemainingValidity computes a human-readable duration until expiration.
func CalculateRemainingValidity(validBefore time.Time) string {
	now := time.Now()
	if now.After(validBefore) {
		return "Expired"
	}
	remaining := validBefore.Sub(now)
	days := int(remaining.Hours()) / 24
	hours := int(remaining.Hours()) % 24
	if days > 0 {
		return fmt.Sprintf("%dd %dh", days, hours)
	}
	minutes := int(remaining.Minutes()) % 60
	if hours > 0 {
		return fmt.Sprintf("%dh %dm", hours, minutes)
	}
	return fmt.Sprintf("%dm", minutes)
}
