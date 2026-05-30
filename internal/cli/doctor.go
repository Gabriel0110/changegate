package cli

import (
	"runtime"

	"github.com/spf13/cobra"
)

type doctorResult struct {
	Status        string         `json:"status"`
	NetworkCalls  bool           `json:"network_calls"`
	CloudRequired bool           `json:"cloud_required"`
	GoOS          string         `json:"goos"`
	GoArch        string         `json:"goarch"`
	ExitCodes     map[int]string `json:"exit_codes"`
}

func newDoctorCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Check local ChangeGate CLI readiness",
		RunE: func(cmd *cobra.Command, _ []string) error {
			state, err := appFrom(cmd)
			if err != nil {
				return err
			}

			result := doctorResult{
				Status:        "ok",
				NetworkCalls:  false,
				CloudRequired: false,
				GoOS:          runtime.GOOS,
				GoArch:        runtime.GOARCH,
				ExitCodes:     exitCodeMeanings(),
			}

			state.logger.Debug("doctor completed")
			return writeCommandOutput(state, "doctor", result, func(r renderer) {
				r.printf("Status: %s\n", r.successWord("OK"))
				r.printf("Default scan mode: offline\n")
				r.printf("Cloud credentials required: no\n")
				r.printf("Network calls: none\n")
				r.printf("Platform: %s/%s\n", result.GoOS, result.GoArch)
			})
		},
	}

	return cmd
}
