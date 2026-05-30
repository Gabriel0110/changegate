package cli

import (
	"strings"

	"github.com/Gabriel0110/changegate/internal/rules"
	"github.com/spf13/cobra"
)

type ruleListItem struct {
	ID         string       `json:"id"`
	Title      string       `json:"title"`
	Category   string       `json:"category"`
	Severity   string       `json:"severity"`
	Confidence string       `json:"confidence"`
	Status     rules.Status `json:"status"`
	Version    string       `json:"version"`
	Enabled    bool         `json:"enabled"`
}

func newRulesCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rules",
		Short: "Inspect built-in ChangeGate rules",
	}
	cmd.AddCommand(newRulesListCommand())
	cmd.AddCommand(newRulesDescribeCommand())
	return cmd
}

func newRulesListCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List built-in rules",
		RunE: func(cmd *cobra.Command, _ []string) error {
			state, err := appFrom(cmd)
			if err != nil {
				return err
			}
			registry, err := rules.DefaultRegistry()
			if err != nil {
				return internalError(err.Error(), "Report this as a ChangeGate bug.")
			}
			defaultEnabled := defaultEnabledRules()
			items := make([]ruleListItem, 0)
			for _, rule := range registry.Rules() {
				meta := rule.Metadata()
				items = append(items, ruleListItem{
					ID:         meta.ID,
					Title:      meta.Title,
					Category:   string(meta.Category),
					Severity:   string(meta.Severity),
					Confidence: string(meta.Confidence),
					Status:     meta.Status,
					Version:    meta.Version,
					Enabled:    defaultEnabled[meta.ID],
				})
			}

			return writeCommandOutput(state, "rules list", items, func(r renderer) {
				r.printf("Rules:\n")
				for _, item := range items {
					stateLabel := "disabled"
					if item.Enabled {
						stateLabel = "enabled"
					}
					r.printf("  %s  %s  %s  %s\n", item.ID, item.Status, stateLabel, item.Title)
				}
			})
		},
	}
	return cmd
}

func newRulesDescribeCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "describe <rule-id>",
		Short: "Describe a built-in rule",
		Args: func(_ *cobra.Command, args []string) error {
			if len(args) != 1 {
				return usageError("rules describe requires one rule ID", "Run changegate rules list to see available rule IDs.")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			state, err := appFrom(cmd)
			if err != nil {
				return err
			}
			registry, err := rules.DefaultRegistry()
			if err != nil {
				return internalError(err.Error(), "Report this as a ChangeGate bug.")
			}
			rule, ok := registry.Get(args[0])
			if !ok {
				return usageError("unknown rule "+args[0], "Run changegate rules list to see available rule IDs.")
			}
			meta := rule.Metadata()
			return writeCommandOutput(state, "rules describe", meta, func(r renderer) {
				r.printf("%s\n", meta.ID)
				r.printf("%s\n\n", meta.Title)
				r.printf("%s\n\n", meta.Description)
				r.printf("Category: %s\n", meta.Category)
				r.printf("Severity: %s\n", meta.Severity)
				r.printf("Confidence: %s\n", meta.Confidence)
				r.printf("Status: %s\n", meta.Status)
				r.printf("Version: %s\n", meta.Version)
				r.printf("Resources: %s\n", strings.Join(meta.Resources, ", "))
			})
		},
	}
	return cmd
}

func defaultEnabledRules() map[string]bool {
	enabled := make(map[string]bool)
	for _, pack := range rules.DefaultPolicyPacks() {
		for _, ruleID := range pack.Rules {
			enabled[ruleID] = true
		}
	}
	registry, err := rules.DefaultRegistry()
	if err != nil {
		return enabled
	}
	for _, rule := range registry.Rules() {
		meta := rule.Metadata()
		if meta.Status == rules.StatusExperimental || meta.Status == rules.StatusDeprecated {
			enabled[meta.ID] = false
		}
	}
	return enabled
}
