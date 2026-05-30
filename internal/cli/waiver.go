package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/Gabriel0110/changegate/internal/waiver"
	"github.com/spf13/cobra"
)

type waiverFileOptions struct {
	file string
}

type waiverAddOptions struct {
	file                string
	id                  string
	ruleID              string
	resource            string
	fingerprint         string
	owner               string
	reason              string
	expiresAt           string
	environment         string
	evidenceFingerprint string
}

type waiverValidateOptions struct {
	file              string
	maxDurationDays   int
	requireExpiration bool
}

type waiverReportOptions struct {
	file              string
	planPaths         []string
	maxDurationDays   int
	requireExpiration bool
}

func newWaiverCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "waiver",
		Short: "Manage reviewed finding waivers",
	}
	cmd.AddCommand(newWaiverAddCommand())
	cmd.AddCommand(newWaiverListCommand())
	cmd.AddCommand(newWaiverValidateCommand())
	cmd.AddCommand(newWaiverPruneCommand())
	cmd.AddCommand(newWaiverReportCommand())
	return cmd
}

func newWaiverAddCommand() *cobra.Command {
	opts := &waiverAddOptions{}
	cmd := &cobra.Command{
		Use:   "add --file .changegate/waivers.yaml --rule AWS_RULE --resource aws_resource.name",
		Short: "Add a reviewed waiver",
		RunE: func(cmd *cobra.Command, _ []string) error {
			state, err := appFrom(cmd)
			if err != nil {
				return err
			}
			if opts.file == "" {
				return usageError("waiver add requires --file", "Use .changegate/waivers.yaml for reviewable waivers.")
			}
			if opts.owner == "" {
				return usageError("waiver add requires --owner", "Set the accountable owner, for example --owner platform@example.com.")
			}
			if opts.reason == "" {
				return usageError("waiver add requires --reason", "Explain why this exception is acceptable.")
			}
			if opts.expiresAt == "" {
				return usageError("waiver add requires --expires-at", "Waivers must expire by default, for example --expires-at 2026-08-01.")
			}
			if opts.ruleID == "" && opts.resource == "" && opts.fingerprint == "" {
				return usageError("waiver add requires --rule, --resource, or --fingerprint", "Prefer exact --fingerprint scope when available.")
			}
			if _, err := time.Parse("2006-01-02", opts.expiresAt); err != nil {
				return usageError("--expires-at must be YYYY-MM-DD", "Example: --expires-at 2026-08-01")
			}
			file, err := loadWaiverFileOrEmpty(opts.file)
			if err != nil {
				return inputError(err.Error(), "Check the waiver file path.")
			}
			id := opts.id
			if id == "" {
				id = waiver.NextID(file)
			}
			file.Waivers = append(file.Waivers, waiver.Record{
				ID:          id,
				RuleID:      opts.ruleID,
				Resource:    opts.resource,
				Fingerprint: opts.fingerprint,
				Owner:       opts.owner,
				Reason:      opts.reason,
				CreatedAt:   time.Now().UTC().Format("2006-01-02"),
				ExpiresAt:   opts.expiresAt,
				Conditions: waiver.Conditions{
					Environment:         opts.environment,
					EvidenceFingerprint: opts.evidenceFingerprint,
				},
			})
			validation := waiver.Validate(file, waiver.ValidationOptions{RequireExpiration: true, Now: time.Now().UTC()})
			if !validation.Valid {
				return policyError(validation.Diagnostics[0].Message, "Fix waiver fields and retry.")
			}
			if err := writeWaiverFile(opts.file, file); err != nil {
				return err
			}
			result := struct {
				File string `json:"file"`
				ID   string `json:"id"`
			}{File: opts.file, ID: id}
			return writeCommandOutput(state, "waiver add", result, func(r renderer) {
				r.printf("Waiver: %s\n", id)
				r.printf("File: %s\n", opts.file)
				r.printf("Next: review and commit the waiver file.\n")
			})
		},
	}
	cmd.Flags().StringVar(&opts.file, "file", "", "waiver YAML file")
	cmd.Flags().StringVar(&opts.id, "id", "", "waiver ID; generated when omitted")
	cmd.Flags().StringVar(&opts.ruleID, "rule", "", "rule ID scope")
	cmd.Flags().StringVar(&opts.resource, "resource", "", "resource address scope")
	cmd.Flags().StringVar(&opts.fingerprint, "fingerprint", "", "exact finding fingerprint scope")
	cmd.Flags().StringVar(&opts.owner, "owner", "", "accountable waiver owner")
	cmd.Flags().StringVar(&opts.reason, "reason", "", "reviewable waiver reason")
	cmd.Flags().StringVar(&opts.expiresAt, "expires-at", "", "expiration date in YYYY-MM-DD")
	cmd.Flags().StringVar(&opts.environment, "environment", "", "environment condition")
	cmd.Flags().StringVar(&opts.evidenceFingerprint, "evidence-fingerprint", "", "invalidate if finding fingerprint changes")
	return cmd
}

func newWaiverListCommand() *cobra.Command {
	opts := &waiverFileOptions{}
	cmd := &cobra.Command{
		Use:   "list --file .changegate/waivers.yaml",
		Short: "List waivers",
		RunE: func(cmd *cobra.Command, _ []string) error {
			state, err := appFrom(cmd)
			if err != nil {
				return err
			}
			file, err := waiver.LoadFile(opts.file)
			if err != nil {
				return inputError(err.Error(), "Check the waiver file path.")
			}
			return writeCommandOutput(state, "waiver list", file.Waivers, func(r renderer) {
				r.printf("Waivers:\n")
				for _, record := range file.Waivers {
					r.printf("  %s  rule=%s  resource=%s  expires=%s  owner=%s\n", record.ID, record.Rule(), record.Resource, record.ExpiresAt, record.Owner)
				}
			})
		},
	}
	cmd.Flags().StringVar(&opts.file, "file", ".changegate/waivers.yaml", "waiver YAML file")
	return cmd
}

func newWaiverValidateCommand() *cobra.Command {
	opts := &waiverValidateOptions{requireExpiration: true}
	cmd := &cobra.Command{
		Use:   "validate --file .changegate/waivers.yaml",
		Short: "Validate waiver governance",
		RunE: func(cmd *cobra.Command, _ []string) error {
			state, err := appFrom(cmd)
			if err != nil {
				return err
			}
			file, err := waiver.LoadFile(opts.file)
			if err != nil {
				return inputError(err.Error(), "Check the waiver file path.")
			}
			result := waiver.Validate(file, waiver.ValidationOptions{RequireExpiration: opts.requireExpiration, MaxDurationDays: opts.maxDurationDays, Now: time.Now().UTC()})
			if !result.Valid {
				return policyError(result.Diagnostics[0].Message, "Fix the waiver file and rerun validation.")
			}
			return writeCommandOutput(state, "waiver validate", result, func(r renderer) {
				r.printf("Waivers: valid\n")
				r.printf("Total: %d\n", result.Summary.Total)
				r.printf("Active: %d\n", result.Summary.Active)
				r.printf("Expired: %d\n", result.Summary.Expired)
				r.printf("Broad: %d\n", result.Summary.Broad)
				for _, diagnostic := range result.Diagnostics {
					r.printf("Warning: %s\n", diagnostic.Message)
				}
			})
		},
	}
	cmd.Flags().StringVar(&opts.file, "file", ".changegate/waivers.yaml", "waiver YAML file")
	cmd.Flags().IntVar(&opts.maxDurationDays, "max-duration-days", 0, "fail when waiver duration exceeds this many days")
	cmd.Flags().BoolVar(&opts.requireExpiration, "require-expiration", true, "require expires_at on each waiver")
	return cmd
}

func newWaiverPruneCommand() *cobra.Command {
	opts := &waiverFileOptions{}
	var dryRun bool
	cmd := &cobra.Command{
		Use:   "prune --file .changegate/waivers.yaml",
		Short: "Remove expired waivers",
		RunE: func(cmd *cobra.Command, _ []string) error {
			state, err := appFrom(cmd)
			if err != nil {
				return err
			}
			file, err := waiver.LoadFile(opts.file)
			if err != nil {
				return inputError(err.Error(), "Check the waiver file path.")
			}
			next, pruned := waiver.PruneExpired(file, time.Now().UTC())
			if !dryRun {
				if err := writeWaiverFile(opts.file, next); err != nil {
					return err
				}
			}
			result := struct {
				File   string          `json:"file"`
				Pruned []waiver.Record `json:"pruned"`
				DryRun bool            `json:"dry_run"`
			}{File: opts.file, Pruned: pruned, DryRun: dryRun}
			return writeCommandOutput(state, "waiver prune", result, func(r renderer) {
				r.printf("Pruned: %d\n", len(pruned))
				if dryRun {
					r.printf("Dry run: true\n")
				}
				for _, record := range pruned {
					r.printf("Expired waiver: %s\n", record.ID)
				}
			})
		},
	}
	cmd.Flags().StringVar(&opts.file, "file", ".changegate/waivers.yaml", "waiver YAML file")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "show expired waivers without writing")
	return cmd
}

func newWaiverReportCommand() *cobra.Command {
	opts := &waiverReportOptions{requireExpiration: true}
	cmd := &cobra.Command{
		Use:   "report --file .changegate/waivers.yaml --plan tfplan.json",
		Short: "Report waiver application against current findings",
		RunE: func(cmd *cobra.Command, _ []string) error {
			state, err := appFrom(cmd)
			if err != nil {
				return err
			}
			if len(opts.planPaths) == 0 {
				return usageError("waiver report requires at least one --plan", "Pass current plan JSON with --plan.")
			}
			file, err := waiver.LoadFile(opts.file)
			if err != nil {
				return inputError(err.Error(), "Check the waiver file path.")
			}
			validation := waiver.Validate(file, waiver.ValidationOptions{RequireExpiration: opts.requireExpiration, MaxDurationDays: opts.maxDurationDays, Now: time.Now().UTC()})
			report, err := reportForBaseline(cmd, state, opts.planPaths)
			if err != nil {
				return err
			}
			_, review := waiver.Apply(file, report.Findings, time.Now().UTC(), false)
			review.Diagnostics = append(validation.Diagnostics, review.Diagnostics...)
			return writeCommandOutput(state, "waiver report", review, func(r renderer) {
				r.printf("Applied: %d\n", review.Summary.Applied)
				r.printf("Invalid: %d\n", review.Summary.Invalid)
				r.printf("Unused: %d\n", review.Summary.Unused)
				for _, diagnostic := range review.Diagnostics {
					r.printf("Warning: %s\n", diagnostic.Message)
				}
				for _, app := range review.Applications {
					r.printf("Waiver %s: %s\n", app.WaiverID, app.Reason)
				}
			})
		},
	}
	cmd.Flags().StringVar(&opts.file, "file", ".changegate/waivers.yaml", "waiver YAML file")
	cmd.Flags().StringArrayVar(&opts.planPaths, "plan", nil, "path to Terraform/OpenTofu plan JSON; repeat for multiple plans")
	cmd.Flags().IntVar(&opts.maxDurationDays, "max-duration-days", 0, "fail when waiver duration exceeds this many days")
	cmd.Flags().BoolVar(&opts.requireExpiration, "require-expiration", true, "require expires_at on each waiver")
	return cmd
}

func loadWaiverFileOrEmpty(path string) (waiver.File, error) {
	file, err := waiver.LoadFile(path)
	if err == nil {
		return file, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return waiver.File{Version: waiver.Version}, nil
	}
	return waiver.File{}, err
}

func writeWaiverFile(path string, file waiver.File) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return inputError(err.Error(), "Check permissions for the waiver directory.")
	}
	var buf bytes.Buffer
	if err := waiver.Write(&buf, file); err != nil {
		return internalError(err.Error(), "Report this as a ChangeGate bug.")
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		return inputError(err.Error(), "Check permissions for the waiver file.")
	}
	return nil
}
