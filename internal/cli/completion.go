package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newCompletionCommand(root *cobra.Command) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "completion [bash|zsh|fish]",
		Short: "Generate shell completion scripts",
		Args: func(_ *cobra.Command, args []string) error {
			if len(args) != 1 {
				return usageError("completion requires one shell: bash, zsh, or fish", "Run changegate completion bash, zsh, or fish.")
			}
			switch args[0] {
			case "bash", "zsh", "fish":
				return nil
			default:
				return usageError("unsupported shell "+args[0], "Supported shells are bash, zsh, and fish.")
			}
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			switch args[0] {
			case "bash":
				return root.GenBashCompletion(cmd.OutOrStdout())
			case "zsh":
				return root.GenZshCompletion(cmd.OutOrStdout())
			case "fish":
				return root.GenFishCompletion(cmd.OutOrStdout(), true)
			default:
				return fmt.Errorf("unreachable shell %q", args[0])
			}
		},
	}

	return cmd
}
