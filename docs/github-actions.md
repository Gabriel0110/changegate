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
  pull-requests: write
  issues: write
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
          CHANGEGATE_VERSION: v0.2.0
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
          changegate scan --plan tfplan.json --format json --out changegate.json --audit-bundle changegate-audit.zip || status=$?
          changegate scan --plan tfplan.json --format sarif --out changegate.sarif || true
          echo "exit_code=$status" >> "$GITHUB_OUTPUT"
      - name: Post ChangeGate review
        if: always() && github.event_name == 'pull_request'
        working-directory: infra
        env:
          GITHUB_TOKEN: ${{ github.token }}
        run: |
          changegate review github \
            --report changegate.json \
            --comment \
            --annotations \
            --step-summary \
            --artifact "Audit bundle=${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}" || true
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
- uses: Gabriel0110/changegate@v0.2.0
  with:
    version: v0.2.0
    plan: infra/tfplan.json
    format: table
```

## Audit-First Mode

For the first rollout phase:

```bash
changegate scan --plan tfplan.json --mode audit --audit-bundle changegate-audit.zip
```

Audit mode records the decision and evidence but does not return the blocking exit code.

## Pull Request Review Bot

`changegate review github` updates one sticky PR comment marked with `<!-- changegate-review -->`, so rerunning CI updates the existing review instead of posting duplicates. It detects `GITHUB_REPOSITORY`, `GITHUB_EVENT_PATH`, `GITHUB_SHA`, and `GITHUB_TOKEN` in GitHub Actions. Outside Actions, pass `--repo owner/repo`, `--pr 123`, and `--token env:MY_TOKEN`.

Required token permissions:

* `contents: read` to check out repository content.
* `issues: write` to create or update the sticky PR comment.
* `pull-requests: write` when using pull request metadata or future inline review comments.
* `security-events: write` only when uploading SARIF.

Use `--dry-run` to validate configuration without calling the GitHub API:

```bash
changegate review github --report changegate.json --comment --dry-run --repo owner/repo --pr 123
```

For untrusted fork pull requests, avoid running arbitrary Terraform or repository scripts with a write token. Prefer generating the plan in a read-only `pull_request` workflow, or use `pull_request_target` only with a reviewed checkout strategy and least-privilege permissions.

Do not use `pull_request_target` with a direct checkout of an untrusted branch and a write-capable `GITHUB_TOKEN`. If you need comments on fork PRs, split the workflow so untrusted code produces artifacts with read-only permissions and a trusted follow-up job posts the ChangeGate summary from those artifacts.
