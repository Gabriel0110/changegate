# CI Adoption

ChangeGate is designed for read-only CI workflows. It does not require a SaaS account, API key, cloud credentials, or network calls in the default scan path.

## Detect CI

```bash
changegate ci detect
changegate ci detect --format json
```

Detection supports GitHub Actions, GitLab CI, CircleCI, Buildkite, Jenkins, and Atlantis. The command reports only non-secret metadata such as provider, branch, pull request status, repository, and supported review surfaces.

## GitHub Actions

After Terraform plan generation, the minimum ChangeGate addition is:

```yaml
- name: ChangeGate scan
  id: changegate
  working-directory: infra
  run: |
    status=0
    changegate scan --plan tfplan.json --format sarif --out changegate.sarif || status=$?
    echo "exit_code=$status" >> "$GITHUB_OUTPUT"
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: infra/changegate.sarif
- name: Enforce ChangeGate decision
  if: always() && steps.changegate.outputs.exit_code != '0'
  run: exit "${{ steps.changegate.outputs.exit_code }}"
```

Generate a complete workflow:

```bash
changegate ci github --working-directory infra > .github/workflows/changegate.yml
```

Install it directly:

```bash
changegate ci install github --working-directory infra
```

## GitLab CI

```bash
changegate ci gitlab --working-directory infra
```

The generated job emits GitLab Code Quality and JUnit artifacts.

## Other CI Systems

Examples are available in [../examples/ci](../examples/ci):

* CircleCI: publish JUnit and Markdown artifacts.
* Buildkite: use GitHub-style annotation output or upload Markdown artifacts.
* Jenkins: publish JUnit XML and archive Markdown/JSON artifacts.
* Atlantis: run ChangeGate in a custom workflow after producing `terraform show -json`.
* Terraform Cloud/Enterprise: run ChangeGate from a run task-compatible external worker that receives or downloads plan JSON, then reports status back through your existing automation.

## Monorepos

Use one job per Terraform root when roots have separate ownership or different policies:

```bash
changegate scan --plan services/api/tfplan.json --policy services/api/.changegate.yaml
changegate scan --plan platforms/network/tfplan.json --policy platforms/network/.changegate.yaml
```

Use repeated `--plan` flags when a single policy should gate a coordinated change:

```bash
changegate scan \
  --plan services/api/tfplan.json \
  --plan platforms/network/tfplan.json \
  --format markdown \
  --out changegate-summary.md
```

## Multi-workspace Terraform repos

Generate one plan JSON per workspace and pass each plan to ChangeGate:

```bash
for workspace in dev stage prod; do
  terraform workspace select "$workspace"
  terraform plan -out="tfplan-$workspace"
  terraform show -json "tfplan-$workspace" > "tfplan-$workspace.json"
done

changegate scan \
  --plan tfplan-dev.json \
  --plan tfplan-stage.json \
  --plan tfplan-prod.json
```

## Rollout path: audit first

Start in audit mode for one to two weeks:

```bash
changegate scan --plan tfplan.json --mode audit --format markdown --out changegate.md
```

Then move to warning mode:

```bash
changegate scan --plan tfplan.json --mode warn
```

Finally enforce default blocking:

```bash
changegate scan --plan tfplan.json --mode block
```

## Rollout path: block only new critical risks

Use a conservative policy during early enforcement:

```yaml
version: 1
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
```

Then run:

```bash
changegate scan --plan tfplan.json --policy .changegate/new-critical-only.yaml
```

## Caching

Use `--cache-dir` to create stable CI cache directories for policy packs and future cloud-context snapshots:

```bash
changegate scan --plan tfplan.json --cache-dir .changegate/cache
```

Cache these paths in CI:

* `.changegate/cache/policy-packs`
* `.changegate/cache/cloud-context`
