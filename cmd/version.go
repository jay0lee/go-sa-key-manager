package cmd

import (
	"fmt"
	"runtime"

	"github.com/jay0lee/go-sa-key-manager/pkg/output"
	"github.com/spf13/cobra"
)

var (
	// Version is set via ldflags at build time.
	Version = "1.0.0"
	// GitCommit is set via ldflags at build time.
	GitCommit = "dev"
	// BuildDate is set via ldflags at build time.
	BuildDate = "unknown"
)

// VersionInfo stores build and version metadata.
type VersionInfo struct {
	Version   string `json:"version" yaml:"version"`
	GitCommit string `json:"git_commit" yaml:"git_commit"`
	BuildDate string `json:"build_date" yaml:"build_date"`
	GoVersion string `json:"go_version" yaml:"go_version"`
	Platform  string `json:"platform" yaml:"platform"`
}

func newVersionCmd(app *App) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Display version, build, and platform information",
		RunE: func(cmd *cobra.Command, args []string) error {
			info := VersionInfo{
				Version:   Version,
				GitCommit: GitCommit,
				BuildDate: BuildDate,
				GoVersion: runtime.Version(),
				Platform:  fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
			}

			if app.Format == "json" {
				return output.PrintJSON(app.Out, info)
			}
			if app.Format == "yaml" {
				return output.PrintYAML(app.Out, info)
			}

			fmt.Fprintf(app.Out, "gcp-sa-key-manager version %s (%s)\n", info.Version, info.GitCommit)
			fmt.Fprintf(app.Out, "  Built:    %s\n", info.BuildDate)
			fmt.Fprintf(app.Out, "  Go:       %s\n", info.GoVersion)
			fmt.Fprintf(app.Out, "  Platform: %s\n", info.Platform)
			return nil
		},
	}

	return cmd
}
