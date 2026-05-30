package cli

import (
	"github.com/Gabriel0110/changegate/internal/buildinfo"
	"github.com/spf13/cobra"
)

func newVersionCommand() *cobra.Command {
	var jsonOutput bool

	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print ChangeGate version information",
		RunE: func(cmd *cobra.Command, _ []string) error {
			state, err := appFrom(cmd)
			if err != nil {
				return err
			}

			info := buildinfo.Current()
			if jsonOutput {
				return writeJSON(state.renderer.out, jsonEnvelope{
					OK:      true,
					Command: "version",
					Result:  info,
				})
			}

			return writeCommandOutput(state, "version", info, func(r renderer) {
				r.printf("changegate %s\n", info.Version)
				r.printf("commit: %s\n", info.Commit)
				r.printf("built: %s\n", info.Date)
			})
		},
	}

	cmd.Flags().BoolVar(&jsonOutput, "json", false, "print version information as JSON")
	return cmd
}
