package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Gabriel0110/changegate/internal/ci"
	"github.com/spf13/cobra"
)

type ciSnippetOptions struct {
	planPath         string
	workingDirectory string
	auditFirst       bool
	newCriticalOnly  bool
}

func newCICommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ci",
		Short: "Generate CI snippets and detect CI environments",
	}
	cmd.AddCommand(newCIDetectCommand())
	cmd.AddCommand(newCIGitHubCommand())
	cmd.AddCommand(newCIGitLabCommand())
	cmd.AddCommand(newCIInstallCommand())
	return cmd
}

func newCIDetectCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "detect",
		Short: "Detect the current CI environment",
		RunE: func(cmd *cobra.Command, _ []string) error {
			state, err := appFrom(cmd)
			if err != nil {
				return err
			}
			result := ci.Detect(environMap(os.Environ()))
			return writeCommandOutput(state, "ci detect", result, func(r renderer) {
				if result.Detected {
					r.printf("CI: %s\n", result.Name)
				} else {
					r.printf("CI: not detected\n")
				}
				r.printf("Provider: %s\n", result.Provider)
				r.printf("Pull request: %t\n", result.PullRequest)
				if result.Branch != "" {
					r.printf("Branch: %s\n", result.Branch)
				}
				if result.Repository != "" {
					r.printf("Repository: %s\n", result.Repository)
				}
				r.printf("SARIF: %t\n", result.SupportsSARIF)
				r.printf("Annotations: %t\n", result.SupportsAnnotations)
				r.printf("Step summary: %t\n", result.SupportsStepSummary)
				for _, note := range result.Notes {
					r.printf("Next: %s\n", note)
				}
			})
		},
	}
	return cmd
}

func newCIGitHubCommand() *cobra.Command {
	opts := &ciSnippetOptions{}
	cmd := &cobra.Command{
		Use:   "github",
		Short: "Print a GitHub Actions ChangeGate workflow",
		RunE: func(cmd *cobra.Command, _ []string) error {
			state, err := appFrom(cmd)
			if err != nil {
				return err
			}
			snippet := ci.GitHubWorkflow(toSnippetOptions(opts))
			_, err = fmt.Fprint(state.renderer.out, snippet)
			return err
		},
	}
	addSnippetFlags(cmd, opts)
	return cmd
}

func newCIGitLabCommand() *cobra.Command {
	opts := &ciSnippetOptions{}
	cmd := &cobra.Command{
		Use:   "gitlab",
		Short: "Print a GitLab CI ChangeGate job",
		RunE: func(cmd *cobra.Command, _ []string) error {
			state, err := appFrom(cmd)
			if err != nil {
				return err
			}
			snippet := ci.GitLabCI(toSnippetOptions(opts))
			_, err = fmt.Fprint(state.renderer.out, snippet)
			return err
		},
	}
	addSnippetFlags(cmd, opts)
	return cmd
}

func newCIInstallCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "install",
		Short: "Install CI workflow files",
	}
	cmd.AddCommand(newCIInstallGitHubCommand())
	return cmd
}

func newCIInstallGitHubCommand() *cobra.Command {
	opts := &ciSnippetOptions{}
	var path string
	var force bool
	cmd := &cobra.Command{
		Use:   "github",
		Short: "Install a GitHub Actions ChangeGate workflow",
		RunE: func(cmd *cobra.Command, _ []string) error {
			state, err := appFrom(cmd)
			if err != nil {
				return err
			}
			if path == "" {
				path = filepath.Join(".github", "workflows", "changegate.yml")
			}
			if !force {
				if _, err := os.Stat(path); err == nil {
					return usageError("workflow already exists at "+path, "Pass --force to overwrite it or choose --path.")
				} else if !os.IsNotExist(err) {
					return inputError(err.Error(), "Check the workflow path.")
				}
			}
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				return inputError(err.Error(), "Check permissions for the workflow directory.")
			}
			snippet := ci.GitHubWorkflow(toSnippetOptions(opts))
			if err := os.WriteFile(path, []byte(snippet), 0o644); err != nil {
				return inputError(err.Error(), "Check permissions for the workflow path.")
			}
			if state.opts.format == "json" {
				return writeJSON(state.renderer.out, jsonEnvelope{OK: true, Command: "ci install github", Result: map[string]string{"path": path}})
			}
			state.renderer.printf("Installed GitHub Actions workflow: %s\n", path)
			state.renderer.printf("Next: generate Terraform plan JSON in the configured working directory, then open a pull request.\n")
			return nil
		},
	}
	addSnippetFlags(cmd, opts)
	cmd.Flags().StringVar(&path, "path", "", "workflow path to write")
	cmd.Flags().BoolVar(&force, "force", false, "overwrite an existing workflow file")
	return cmd
}

func addSnippetFlags(cmd *cobra.Command, opts *ciSnippetOptions) {
	cmd.Flags().StringVar(&opts.planPath, "plan", "tfplan.json", "plan JSON path inside the Terraform working directory")
	cmd.Flags().StringVar(&opts.workingDirectory, "working-directory", "infra", "Terraform working directory")
	cmd.Flags().BoolVar(&opts.auditFirst, "audit-first", false, "generate audit-only rollout commands")
	cmd.Flags().BoolVar(&opts.newCriticalOnly, "new-critical-only", false, "reference the new critical risks rollout policy")
}

func toSnippetOptions(opts *ciSnippetOptions) ci.SnippetOptions {
	return ci.SnippetOptions{
		PlanPath:         opts.planPath,
		WorkingDirectory: opts.workingDirectory,
		AuditFirst:       opts.auditFirst,
		NewCriticalOnly:  opts.newCriticalOnly,
	}
}

func environMap(values []string) map[string]string {
	out := make(map[string]string, len(values))
	for _, value := range values {
		key, val, ok := strings.Cut(value, "=")
		if !ok {
			continue
		}
		out[key] = val
	}
	return out
}
