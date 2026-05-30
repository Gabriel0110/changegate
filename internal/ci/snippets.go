package ci

import "fmt"

// SnippetOptions controls generated CI snippets.
type SnippetOptions struct {
	PlanPath         string
	WorkingDirectory string
	AuditFirst       bool
	NewCriticalOnly  bool
}

// GitHubWorkflow returns a copy-paste GitHub Actions workflow.
func GitHubWorkflow(opts SnippetOptions) string {
	planPath := defaultString(opts.PlanPath, "tfplan.json")
	workingDirectory := defaultString(opts.WorkingDirectory, "infra")
	mode := "block"
	if opts.AuditFirst {
		mode = "audit"
	}
	policy := ""
	if opts.NewCriticalOnly {
		policy = " --policy .changegate/new-critical-only.yaml"
	}
	return fmt.Sprintf(`name: infrastructure-risk

on:
  pull_request:
    paths:
      - "%s/**"

permissions:
  contents: read
  security-events: write

jobs:
  changegate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: hashicorp/setup-terraform@v3
      - name: Terraform plan
        working-directory: %s
        run: |
          terraform init
          terraform plan -out=tfplan
          terraform show -json tfplan > %s
      - name: Install ChangeGate
        env:
          CHANGEGATE_VERSION: vX.Y.Z
          CHANGEGATE_INSTALL_DIR: ${{ runner.temp }}/changegate-bin
        run: |
          curl -fsSL "https://raw.githubusercontent.com/Gabriel0110/changegate/${CHANGEGATE_VERSION}/scripts/install.sh" -o /tmp/install-changegate.sh
          bash /tmp/install-changegate.sh
          echo "${CHANGEGATE_INSTALL_DIR}" >> "${GITHUB_PATH}"
      - name: ChangeGate scan
        id: changegate
        working-directory: %s
        run: |
          status=0
          changegate scan --plan %s --mode %s%s --format sarif --out changegate.sarif || status=$?
          changegate scan --plan %s --mode %s%s --format github-step-summary --out "$GITHUB_STEP_SUMMARY" || true
          echo "exit_code=$status" >> "$GITHUB_OUTPUT"
      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: %s/changegate.sarif
      - name: Enforce ChangeGate decision
        if: always() && steps.changegate.outputs.exit_code != '0'
        run: exit "${{ steps.changegate.outputs.exit_code }}"
`, workingDirectory, workingDirectory, planPath, workingDirectory, planPath, mode, policy, planPath, mode, policy, workingDirectory)
}

// GitLabCI returns a GitLab CI job snippet.
func GitLabCI(opts SnippetOptions) string {
	planPath := defaultString(opts.PlanPath, "tfplan.json")
	workingDirectory := defaultString(opts.WorkingDirectory, "infra")
	mode := "block"
	if opts.AuditFirst {
		mode = "audit"
	}
	return fmt.Sprintf(`changegate:
  image:
    name: hashicorp/terraform:1.8
    entrypoint: [""]
  stage: test
  variables:
    CHANGEGATE_VERSION: vX.Y.Z
  before_script:
    - apk add --no-cache bash curl tar perl-utils
    - curl -fsSL "https://raw.githubusercontent.com/Gabriel0110/changegate/${CHANGEGATE_VERSION}/scripts/install.sh" -o /tmp/install-changegate.sh
    - CHANGEGATE_INSTALL_DIR=/usr/local/bin bash /tmp/install-changegate.sh
  script:
    - cd %s
    - terraform init
    - terraform plan -out=tfplan
    - terraform show -json tfplan > %s
    - status=0
    - changegate scan --plan %s --mode %s --format gitlab-code-quality --out "${CI_PROJECT_DIR}/gl-code-quality-report.json" --audit-bundle "${CI_PROJECT_DIR}/changegate-audit.zip" || status=$?
    - changegate scan --plan %s --mode %s --format junit --out "${CI_PROJECT_DIR}/changegate.junit.xml" || true
    - exit "$status"
  artifacts:
    when: always
    paths:
      - changegate-audit.zip
    reports:
      codequality: gl-code-quality-report.json
      junit: changegate.junit.xml
`, workingDirectory, planPath, planPath, mode, planPath, mode)
}

// AuditPolicy returns an audit-first policy file.
func AuditPolicy() string {
	return `version: 1
mode: audit
policy_packs:
  - aws-core
  - aws-public-exposure
  - aws-iam-escalation
`
}

// NewCriticalOnlyPolicy returns a conservative new-risk rollout policy.
func NewCriticalOnlyPolicy() string {
	return `version: 1
mode: block
decision:
  block_on:
    min_severity: critical
    min_confidence: high
  warn_on:
    min_severity: high
    min_confidence: high
scope:
  changed_resources_only: true
baseline:
  mode: new-risk-only
  fingerprints: []
policy_packs:
  - aws-core
  - aws-public-exposure
  - aws-iam-escalation
`
}

func defaultString(value string, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
