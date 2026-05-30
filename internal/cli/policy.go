package cli

import (
	"time"

	"github.com/Gabriel0110/changegate/internal/model"
	"github.com/Gabriel0110/changegate/internal/policy"
	"github.com/Gabriel0110/changegate/internal/rules"
	"github.com/Gabriel0110/changegate/internal/waiver"
	"github.com/spf13/cobra"
)

func newPolicyCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Validate and test ChangeGate policy configuration",
	}
	cmd.AddCommand(newPolicyValidateCommand())
	cmd.AddCommand(newPolicyTestCommand())
	return cmd
}

func newPolicyValidateCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "validate <policy-file>",
		Short: "Validate a ChangeGate policy file",
		Args: func(_ *cobra.Command, args []string) error {
			if len(args) != 1 {
				return usageError("policy validate requires a policy file", "Run changegate policy validate .changegate.yaml.")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			state, err := appFrom(cmd)
			if err != nil {
				return err
			}
			result, err := validatePolicyFile(args[0])
			if err != nil {
				return err
			}
			if !result.Valid {
				return policyError(result.Diagnostics[0].Message, "Fix the policy file and rerun validation.")
			}
			return writeCommandOutput(state, "policy validate", result, func(r renderer) {
				r.printf("Policy: valid\n")
				r.printf("Mode: %s\n", result.Policy.Mode)
				r.printf("Policy packs: %d\n", len(result.Policy.PolicyPacks))
			})
		},
	}
	return cmd
}

func newPolicyTestCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "test <policy-file>",
		Short: "Run policy validation and rule selection checks",
		Args: func(_ *cobra.Command, args []string) error {
			if len(args) != 1 {
				return usageError("policy test requires a policy file", "Run changegate policy test .changegate.yaml.")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			state, err := appFrom(cmd)
			if err != nil {
				return err
			}
			config, err := policy.LoadFile(args[0])
			if err != nil {
				return policyError(err.Error(), "Check the policy path and YAML syntax.")
			}
			registry, customDiagnostics, err := registryForPolicy(args[0], config)
			if err != nil {
				return err
			}
			validation := policy.Validate(config, registry, rules.DefaultPolicyPacks())
			validation.Diagnostics = append(validation.Diagnostics, customDiagnostics...)
			if len(customDiagnostics) > 0 {
				validation.Valid = false
			}
			if !validation.Valid {
				return policyError(validation.Diagnostics[0].Message, "Fix the policy file and rerun validation.")
			}
			selection := policy.RuleSelection(config, rules.DefaultPolicyPacks())
			result := struct {
				Valid         bool `json:"valid"`
				EnabledRules  int  `json:"enabled_rules"`
				DisabledRules int  `json:"disabled_rules"`
				Overrides     int  `json:"overrides"`
				Registered    int  `json:"registered_rules"`
			}{
				Valid:         true,
				EnabledRules:  len(selection.EnabledRules),
				DisabledRules: len(selection.DisabledRules),
				Overrides:     len(selection.Overrides),
				Registered:    len(registry.Rules()),
			}
			return writeCommandOutput(state, "policy test", result, func(r renderer) {
				r.printf("Policy test: passed\n")
				r.printf("Enabled rules: %d\n", result.EnabledRules)
				r.printf("Disabled rules: %d\n", result.DisabledRules)
				r.printf("Overrides: %d\n", result.Overrides)
				r.printf("Registered rules: %d\n", result.Registered)
			})
		},
	}
	return cmd
}

func validatePolicyFile(path string) (policy.ValidationResult, error) {
	config, err := policy.LoadFile(path)
	if err != nil {
		return policy.ValidationResult{}, policyError(err.Error(), "Check the policy path and YAML syntax.")
	}
	registry, customDiagnostics, err := registryForPolicy(path, config)
	if err != nil {
		return policy.ValidationResult{}, err
	}
	result := policy.Validate(config, registry, rules.DefaultPolicyPacks())
	result.Diagnostics = append(result.Diagnostics, customDiagnostics...)
	if len(customDiagnostics) > 0 {
		result.Valid = false
	}
	if result.Valid && config.Waivers.File != "" {
		waiverFile, err := waiver.LoadFile(config.Waivers.File)
		if err != nil {
			result.Valid = false
			result.Diagnostics = append(result.Diagnostics, model.Diagnostic{Severity: model.DiagnosticError, Code: "WAIVER_FILE_INVALID", Message: err.Error()})
			return result, nil
		}
		waiverValidation := waiver.Validate(waiverFile, waiver.ValidationOptions{
			RequireExpiration: true,
			MaxDurationDays:   config.Waivers.MaxDurationDays,
			Now:               time.Now().UTC(),
		})
		for _, diagnostic := range waiverValidation.Diagnostics {
			result.Diagnostics = append(result.Diagnostics, diagnostic)
			if diagnostic.Severity == model.DiagnosticError {
				result.Valid = false
			}
		}
	}
	return result, nil
}

func policyError(message string, fix string) *ExitError {
	return newExitError(exitPolicyConfiguration, "policy", message, fix)
}
