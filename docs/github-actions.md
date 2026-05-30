# GitHub Actions

Use ChangeGate after generating Terraform/OpenTofu plan JSON and before applying.

```yaml
name: infrastructure-risk
on:
  pull_request:
    paths:
      - "infra/**"

permissions:
  contents: read
  security-events: write

jobs:
  changegate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
      - uses: hashicorp/setup-terraform@v3
      - name: Terraform plan
        working-directory: infra
        run: |
          terraform init
          terraform plan -out=tfplan
          terraform show -json tfplan > tfplan.json
      - name: Install ChangeGate
        env:
          CHANGEGATE_VERSION: vX.Y.Z
          CHANGEGATE_INSTALL_DIR: ${{ runner.temp }}/changegate-bin
        run: |
          curl -fsSL "https://raw.githubusercontent.com/Gabriel0110/changegate/${CHANGEGATE_VERSION}/scripts/install.sh" -o /tmp/install-changegate.sh
          bash /tmp/install-changegate.sh
          echo "$CHANGEGATE_INSTALL_DIR" >> "$GITHUB_PATH"
      - name: ChangeGate scan
        id: changegate
        working-directory: infra
        run: |
          status=0
          changegate scan --plan tfplan.json --format sarif --out changegate.sarif --audit-bundle changegate-audit.zip || status=$?
          changegate scan --plan tfplan.json --format github-step-summary --out "$GITHUB_STEP_SUMMARY" || true
          echo "exit_code=$status" >> "$GITHUB_OUTPUT"
      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@4c50b6f6fd9dc6fe03111c2d045c8be2a724cce1 # v3.28.11
        with:
          sarif_file: infra/changegate.sarif
      - name: Upload audit bundle
        if: always()
        uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4.6.2
        with:
          name: changegate-audit
          path: infra/changegate-audit.zip
      - name: Enforce ChangeGate decision
        if: always() && steps.changegate.outputs.exit_code != '0'
        run: exit "${{ steps.changegate.outputs.exit_code }}"
```

## Composite Action

The repository also includes a composite action. The `version` input is required so CI never installs a floating binary:

```yaml
- uses: Gabriel0110/changegate@vX.Y.Z
  with:
    version: vX.Y.Z
    plan: infra/tfplan.json
    format: table
```

## Audit-First Mode

For the first rollout phase:

```bash
changegate scan --plan tfplan.json --mode audit --audit-bundle changegate-audit.zip
```

Audit mode records the decision and evidence but does not return the blocking exit code.
