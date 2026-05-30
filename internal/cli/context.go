package cli

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Gabriel0110/changegate/internal/cloudcontext"
	"github.com/Gabriel0110/changegate/internal/model"
	"github.com/spf13/cobra"
)

func newContextCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "context",
		Short: "Manage optional cloud context snapshots",
	}
	cmd.AddCommand(newContextAWSCommand())
	return cmd
}

func newContextAWSCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "aws",
		Short: "Manage AWS context snapshots",
	}
	cmd.AddCommand(newContextAWSIdentityCommand())
	cmd.AddCommand(newContextAWSSnapshotCommand())
	cmd.AddCommand(newContextAWSPermissionsTemplateCommand())
	cmd.AddCommand(newContextAWSValidatePermissionsCommand())
	return cmd
}

func newContextAWSIdentityCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "identity",
		Short: "Detect non-secret AWS identity metadata from environment",
		RunE: func(cmd *cobra.Command, _ []string) error {
			state, err := appFrom(cmd)
			if err != nil {
				return err
			}
			identity := cloudcontext.DetectAWSIdentity(environMap(os.Environ()))
			return writeCommandOutput(state, "context aws identity", identity, func(r renderer) {
				r.printf("AWS identity detected: %t\n", identity.Detected)
				if identity.AccountID != "" {
					r.printf("Account: %s\n", identity.AccountID)
				}
				if identity.Region != "" {
					r.printf("Region: %s\n", identity.Region)
				}
				if identity.Profile != "" {
					r.printf("Profile: %s\n", identity.Profile)
				}
			})
		},
	}
	return cmd
}

func newContextAWSSnapshotCommand() *cobra.Command {
	var outPath string
	var collectValue string
	var regionsValue string
	var profile string
	var timeoutValue string
	cmd := &cobra.Command{
		Use:   "snapshot --out .changegate/aws-context.json",
		Short: "Create an offline AWS context snapshot",
		RunE: func(cmd *cobra.Command, _ []string) error {
			state, err := appFrom(cmd)
			if err != nil {
				return err
			}
			if outPath == "" {
				return usageError("context aws snapshot requires --out", "Write the snapshot to .changegate/aws-context.json.")
			}
			snapshot, diagnostics, collected, err := buildAWSSnapshot(cmd, collectValue, regionsValue, profile, timeoutValue)
			if err != nil {
				return err
			}
			var buf bytes.Buffer
			if err := cloudcontext.Write(&buf, snapshot); err != nil {
				return internalError(err.Error(), "Report this as a ChangeGate bug.")
			}
			if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
				return inputError(err.Error(), "Check permissions for the context output directory.")
			}
			if err := os.WriteFile(outPath, buf.Bytes(), 0o644); err != nil {
				return inputError(err.Error(), "Check permissions for the context output path.")
			}
			result := struct {
				Path        string `json:"path"`
				Provider    string `json:"provider"`
				AccountID   string `json:"account_id,omitempty"`
				Collected   bool   `json:"collected"`
				Regions     int    `json:"regions"`
				Diagnostics int    `json:"diagnostics"`
			}{Path: outPath, Provider: snapshot.Provider, AccountID: snapshot.Account.ID, Collected: collected, Regions: len(snapshot.Regions), Diagnostics: len(diagnostics)}
			return writeCommandOutput(state, "context aws snapshot", result, func(r renderer) {
				r.printf("AWS context snapshot: %s\n", outPath)
				if collected {
					r.printf("Network calls: AWS read-only APIs\n")
					r.printf("Regions: %d\n", len(snapshot.Regions))
					if len(diagnostics) > 0 {
						r.printf("Diagnostics: %d\n", len(diagnostics))
						for _, diagnostic := range diagnostics {
							r.printf("Warning: %s\n", strings.TrimSpace(diagnostic.Message))
						}
					}
				} else {
					r.printf("Network calls: none\n")
				}
				r.printf("Next: run scan --context-file %s\n", outPath)
			})
		},
	}
	cmd.Flags().StringVar(&outPath, "out", "", "context snapshot path to write")
	cmd.Flags().StringVar(&collectValue, "collect", "", "collect read-only AWS context groups: all, identity, network, edge, iam, data, compute")
	cmd.Flags().StringVar(&regionsValue, "regions", "", "comma-separated AWS regions to collect")
	cmd.Flags().StringVar(&profile, "profile", "", "AWS shared config profile to use for collection")
	cmd.Flags().StringVar(&timeoutValue, "timeout", "2m", "AWS collection timeout")
	if flag := cmd.Flags().Lookup("collect"); flag != nil {
		flag.NoOptDefVal = cloudcontext.CollectAll
	}
	return cmd
}

func buildAWSSnapshot(cmd *cobra.Command, collectValue string, regionsValue string, profile string, timeoutValue string) (cloudcontext.Snapshot, []model.Diagnostic, bool, error) {
	if collectValue == "" {
		identity := cloudcontext.DetectAWSIdentity(environMap(os.Environ()))
		return cloudcontext.NewAWSSnapshot(identity, time.Now().UTC()), nil, false, nil
	}
	groups, err := cloudcontext.ParseCollectGroups(collectValue)
	if err != nil {
		return cloudcontext.Snapshot{}, nil, false, usageError(err.Error(), "Use --collect all or a comma-separated list of identity,network,edge,iam,data,compute.")
	}
	timeout, err := time.ParseDuration(timeoutValue)
	if err != nil || timeout <= 0 {
		return cloudcontext.Snapshot{}, nil, false, usageError("invalid context aws snapshot --timeout", "Use a positive duration such as 30s or 2m.")
	}
	ctx, cancel := context.WithTimeout(cmd.Context(), timeout)
	defer cancel()
	req := cloudcontext.AWSCollectRequest{
		Profile: profile,
		Regions: cloudcontext.ParseRegions(regionsValue),
		Groups:  groups,
		Now:     time.Now().UTC(),
	}
	collector, err := cloudcontext.NewAWSCollector(ctx, req)
	if err != nil {
		return cloudcontext.Snapshot{}, nil, false, inputError(err.Error(), "Check AWS credentials, profile, and region configuration.")
	}
	snapshot, diagnostics, err := collector.Collect(ctx, req)
	if err != nil {
		return cloudcontext.Snapshot{}, nil, false, inputError(err.Error(), "Check AWS credentials, profile, and read-only permissions.")
	}
	return snapshot, diagnostics, true, nil
}

func newContextAWSPermissionsTemplateCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "permissions-template",
		Short: "Print read-only AWS permissions for context collection",
		RunE: func(cmd *cobra.Command, _ []string) error {
			state, err := appFrom(cmd)
			if err != nil {
				return err
			}
			_, err = fmt.Fprint(state.renderer.out, cloudcontext.ReadOnlyPolicyTemplate())
			return err
		},
	}
	return cmd
}

func newContextAWSValidatePermissionsCommand() *cobra.Command {
	var contextFile string
	cmd := &cobra.Command{
		Use:   "validate-permissions --context-file .changegate/aws-context.json",
		Short: "Validate context snapshot capability coverage",
		RunE: func(cmd *cobra.Command, _ []string) error {
			state, err := appFrom(cmd)
			if err != nil {
				return err
			}
			if contextFile == "" {
				return usageError("context aws validate-permissions requires --context-file", "Pass a snapshot created by context aws snapshot.")
			}
			snapshot, err := cloudcontext.LoadFile(contextFile)
			if err != nil {
				return inputError(err.Error(), "Check --context-file.")
			}
			diagnostics := cloudcontext.ValidatePermissions(snapshot)
			result := struct {
				Valid       bool   `json:"valid"`
				ContextFile string `json:"context_file"`
				Warnings    int    `json:"warnings"`
			}{Valid: len(diagnostics) == 0, ContextFile: contextFile, Warnings: len(diagnostics)}
			return writeCommandOutput(state, "context aws validate-permissions", result, func(r renderer) {
				r.printf("Context file: %s\n", contextFile)
				if len(diagnostics) == 0 {
					r.printf("Permissions: complete\n")
					return
				}
				r.printf("Permissions: partial\n")
				for _, diagnostic := range diagnostics {
					r.printf("Warning: %s\n", strings.TrimSpace(diagnostic.Message))
				}
			})
		},
	}
	cmd.Flags().StringVar(&contextFile, "context-file", "", "context snapshot path")
	return cmd
}
