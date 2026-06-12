package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"
)

type initOptions struct {
	githubActions bool
	gitlabCI      bool
	auditMode     bool
	baseline      bool
	waivers       bool
	dryRun        bool
	force         bool
	dir           string
}

type initFile struct {
	Path string `json:"path"`
	Body string `json:"body,omitempty"`
}

type initResult struct {
	Mode    string     `json:"mode"`
	DryRun  bool       `json:"dry_run"`
	Written []string   `json:"written,omitempty"`
	Files   []initFile `json:"files,omitempty"`
}

func newInitCommand() *cobra.Command {
	opts := &initOptions{}
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Create a safe starter ChangeGate configuration",
		Long: `Create starter ChangeGate files for a repository.

The default setup uses audit mode so you can review signal before enforcing
blocking decisions. Add CI and governance files with flags, then edit the
generated files to match your Terraform/OpenTofu layout.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			state, err := appFrom(cmd)
			if err != nil {
				return err
			}
			files := initFiles(*opts)
			if len(files) == 0 {
				return internalError("init produced no files", "Report this as a ChangeGate bug.")
			}
			if opts.dryRun {
				result := initResult{Mode: initMode(opts), DryRun: true, Files: files}
				return writeCommandOutput(state, "init", result, func(r renderer) {
					for _, file := range files {
						r.printf("--- %s\n%s", file.Path, file.Body)
						if !strings.HasSuffix(file.Body, "\n") {
							r.printf("\n")
						}
					}
				})
			}
			if err := writeInitFiles(opts.dir, files, opts.force); err != nil {
				return err
			}
			written := make([]string, 0, len(files))
			for _, file := range files {
				written = append(written, file.Path)
			}
			result := initResult{Mode: initMode(opts), Written: written}
			return writeCommandOutput(state, "init", result, func(r renderer) {
				r.printf("Created ChangeGate starter files:\n")
				for _, path := range written {
					r.printf("  %s\n", path)
				}
				r.printf("Next: generate a Terraform/OpenTofu plan JSON and run changegate scan --plan tfplan.json --policy .changegate.yaml\n")
			})
		},
	}
	cmd.Flags().BoolVar(&opts.githubActions, "github-actions", false, "add .github/workflows/changegate.yml")
	cmd.Flags().BoolVar(&opts.gitlabCI, "gitlab-ci", false, "add .gitlab-ci.yml")
	cmd.Flags().BoolVar(&opts.auditMode, "audit-mode", false, "write audit-mode starter policy; this is also the default")
	cmd.Flags().BoolVar(&opts.baseline, "baseline", false, "add baseline setup instructions under .changegate/")
	cmd.Flags().BoolVar(&opts.waivers, "waivers", false, "add an empty .changegate/waivers.yaml file")
	cmd.Flags().BoolVar(&opts.dryRun, "dry-run", false, "print files without writing")
	cmd.Flags().BoolVar(&opts.force, "force", false, "overwrite existing generated paths")
	cmd.Flags().StringVar(&opts.dir, "dir", ".", "repository directory to initialize")
	return cmd
}

func initMode(_ *initOptions) string {
	return "audit"
}

func initFiles(opts initOptions) []initFile {
	files := []initFile{{
		Path: ".changegate.yaml",
		Body: strings.TrimSpace(`version: 1
mode: audit

policy_packs:
  - aws-core
  - aws-public-exposure
  - aws-iam-escalation

decision:
  block_on:
    min_severity: high
    min_confidence: high
  warn_on:
    min_severity: medium
    min_confidence: medium

review:
  enabled: true
  max_comment_findings: 10
  max_graph_paths: 5

impact:
  include_existing_risks: true
  include_resolved_risks: true
  include_waivers: true

attack_paths:
  enabled: true
`) + "\n",
	}}
	if opts.baseline {
		files = append(files, initFile{Path: ".changegate/README.md", Body: baselineReadme()})
	}
	if opts.waivers {
		files = append(files, initFile{Path: ".changegate/waivers.yaml", Body: "version: 1\nwaivers: []\n"})
	}
	if opts.githubActions {
		files = append(files, initFile{Path: ".github/workflows/changegate.yml", Body: githubActionsWorkflow()})
	}
	if opts.gitlabCI {
		files = append(files, initFile{Path: ".gitlab-ci.yml", Body: gitlabCI()})
	}
	sort.SliceStable(files, func(i int, j int) bool {
		return files[i].Path < files[j].Path
	})
	return files
}

func writeInitFiles(baseDir string, files []initFile, force bool) error {
	if baseDir == "" {
		baseDir = "."
	}
	for _, file := range files {
		target := filepath.Join(baseDir, filepath.FromSlash(file.Path))
		if !force {
			if _, err := os.Stat(target); err == nil {
				return usageError(fmt.Sprintf("%s already exists", file.Path), "Rerun with --force to overwrite, or use --dry-run to preview the generated files.")
			} else if !os.IsNotExist(err) {
				return inputError(err.Error(), "Check repository file permissions.")
			}
		}
	}
	for _, file := range files {
		target := filepath.Join(baseDir, filepath.FromSlash(file.Path))
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return inputError(err.Error(), "Check repository directory permissions.")
		}
		if err := os.WriteFile(target, []byte(file.Body), 0o644); err != nil {
			return inputError(err.Error(), "Check repository file permissions.")
		}
	}
	return nil
}

func baselineReadme() string {
	return strings.TrimSpace(`# ChangeGate State

Create a baseline only after reviewing the current findings:

`+"```bash"+`
changegate baseline create --plan tfplan.json --out .changegate/baseline.json --expires-in-days 90
changegate scan --plan tfplan.json --baseline .changegate/baseline.json --new-only
`+"```"+`

Commit the baseline only when your team accepts the existing risk snapshot.
`) + "\n"
}

func githubActionsWorkflow() string {
	return strings.TrimSpace(`name: changegate

on:
  pull_request:
    paths:
      - "infra/**"

permissions:
  contents: read
  pull-requests: write
  issues: write
  security-events: write

jobs:
  changegate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: hashicorp/setup-terraform@v3

      - name: Terraform plan
        working-directory: infra
        run: |
          terraform init
          terraform plan -out=tfplan
          terraform show -json tfplan > tfplan.json

      - name: Install ChangeGate
        env:
          CHANGEGATE_VERSION: v0.5.0
          CHANGEGATE_INSTALL_DIR: ${{ runner.temp }}/changegate-bin
        run: |
          curl -fsSL "https://raw.githubusercontent.com/Gabriel0110/changegate/${CHANGEGATE_VERSION}/scripts/install.sh" -o /tmp/install-changegate.sh
          bash /tmp/install-changegate.sh
          echo "${CHANGEGATE_INSTALL_DIR}" >> "${GITHUB_PATH}"

      - name: ChangeGate audit review
        working-directory: infra
        env:
          GITHUB_TOKEN: ${{ github.token }}
        run: |
          changegate scan --plan tfplan.json --policy ../.changegate.yaml --mode audit --format json --out changegate.json --audit-bundle changegate-audit.zip
          changegate scan --plan tfplan.json --policy ../.changegate.yaml --mode audit --format sarif --out changegate.sarif || true
          changegate review github --report changegate.json --comment --annotations --step-summary || true

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: infra/changegate.sarif

      - name: Upload audit bundle
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: changegate-audit
          path: infra/changegate-audit.zip
`) + "\n"
}

func gitlabCI() string {
	return strings.TrimSpace(`changegate:
  image:
    name: hashicorp/terraform:1.8
    entrypoint: [""]
  stage: test
  variables:
    CHANGEGATE_VERSION: v0.5.0
  before_script:
    - apk add --no-cache bash curl tar perl-utils
    - curl -fsSL "https://raw.githubusercontent.com/Gabriel0110/changegate/${CHANGEGATE_VERSION}/scripts/install.sh" -o /tmp/install-changegate.sh
    - CHANGEGATE_INSTALL_DIR=/usr/local/bin bash /tmp/install-changegate.sh
  script:
    - cd infra
    - terraform init
    - terraform plan -out=tfplan
    - terraform show -json tfplan > tfplan.json
    - changegate scan --plan tfplan.json --policy ../.changegate.yaml --mode audit --format json --out "${CI_PROJECT_DIR}/changegate.json" --audit-bundle "${CI_PROJECT_DIR}/changegate-audit.zip"
    - changegate scan --plan tfplan.json --policy ../.changegate.yaml --mode audit --format gitlab-code-quality --out "${CI_PROJECT_DIR}/gl-code-quality-report.json" || true
    - changegate review gitlab --report "${CI_PROJECT_DIR}/changegate.json" --comment --code-quality-artifact gl-code-quality-report.json || true
  artifacts:
    when: always
    paths:
      - changegate-audit.zip
      - changegate.json
    reports:
      codequality: gl-code-quality-report.json
`) + "\n"
}
