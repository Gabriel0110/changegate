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
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2
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
- uses: Gabriel0110/changegate@vX.Y.Z
  with:
    version: vX.Y.Z
    plan: infra/tfplan.json
    format: json
    out: infra/changegate.json
    mode: audit
    audit_bundle: infra/changegate-audit.zip
```

The composite action accepts structured inputs for supported scan flags instead of a freeform argument string. Use `mode`, `policy`, `baseline`, `new_only`, `changed_only`, `context_file`, `cloud_context`, `timeout`, `max_findings`, `out`, and `audit_bundle` when you need to tune the scan. Set `verify_sig: "true"` if your runner has `cosign` installed and should verify the signed checksum manifest during install.

## Audit-First Mode

For the first rollout phase:

```bash
changegate scan --plan tfplan.json --mode audit --audit-bundle changegate-audit.zip
```

Audit mode records the decision and evidence but does not return the blocking exit code.

## Pull Request Review Bot

`changegate review github` updates one sticky PR comment marked with `<!-- changegate-review -->`, so rerunning CI updates the existing review instead of posting duplicates. It detects `GITHUB_REPOSITORY`, `GITHUB_EVENT_PATH`, `GITHUB_SHA`, and `GITHUB_TOKEN` in GitHub Actions. Outside Actions, pass `--repo owner/repo`, `--pr 123`, and `--token env:MY_TOKEN`.

Required token permissions:

- `contents: read` to check out repository content.
- `issues: write` to create or update the sticky PR comment.
- `pull-requests: write` when using pull request metadata or review-comment workflows that require pull request API access.
- `security-events: write` only when uploading SARIF.

Use `--dry-run` to validate configuration without calling the GitHub API:

```bash
changegate review github --report changegate.json --comment --dry-run --repo owner/repo --pr 123
```

For untrusted fork pull requests, avoid running arbitrary Terraform or repository scripts with a write token. Prefer generating the plan in a read-only `pull_request` workflow, or use `pull_request_target` only with a reviewed checkout strategy and least-privilege permissions.

Do not use `pull_request_target` with a direct checkout of an untrusted branch and a write-capable `GITHUB_TOKEN`. If you need comments on fork PRs, split the workflow so untrusted code produces artifacts with read-only permissions and a trusted follow-up job posts the ChangeGate summary from those artifacts.
