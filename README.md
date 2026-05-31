# ChangeGate

[![CI](https://github.com/Gabriel0110/changegate/actions/workflows/ci.yml/badge.svg)](https://github.com/Gabriel0110/changegate/actions/workflows/ci.yml)
[![Security](https://github.com/Gabriel0110/changegate/actions/workflows/security.yml/badge.svg)](https://github.com/Gabriel0110/changegate/actions/workflows/security.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/Gabriel0110/changegate.svg)](https://pkg.go.dev/github.com/Gabriel0110/changegate)
[![License](https://img.shields.io/github/license/Gabriel0110/changegate)](LICENSE)

ChangeGate is a fast, graph-aware Terraform/OpenTofu risk gate for CI/CD. It reads the plan that is actually about to apply, builds a graph of changing infrastructure, and returns one deployment decision: `ALLOW`, `WARN`, or `BLOCK`.

It is built for teams that want fewer noisy scanner findings and more trusted deploy decisions.

```bash
terraform plan -out=tfplan
terraform show -json tfplan > tfplan.json
changegate scan --plan tfplan.json
```

By default, ChangeGate runs offline from plan JSON. It does not require a SaaS account, cloud credentials, telemetry, or an AI decision-maker.

## Why ChangeGate

Most IaC scanners inspect source files and produce checklists. ChangeGate gates the planned change.

| ChangeGate focuses on | Why it matters |
| --- | --- |
| Plan-aware analysis | Evaluates the resources and actions Terraform/OpenTofu is about to apply. |
| Graph-aware risk | Understands relationships between load balancers, security groups, IAM, compute, networks, and data stores. |
| High-confidence blocking | Blocks only risks that meet policy, severity, confidence, and context thresholds. |
| One deploy decision | Produces a deterministic allow/warn/block result for CI. |
| Governed exceptions | Supports expiring waivers and baselines for existing debt. |
| Evidence-rich output | Emits findings with evidence, graph paths, remediation, fingerprints, and audit bundles. |

## Review Intelligence

ChangeGate includes review-oriented commands for pull requests, merge requests, approval workflows, and module regression tests:

```bash
changegate impact --plan tfplan.json --format markdown
changegate graph path --plan tfplan.json --from aws_lb.admin --to aws_db_instance.customer
changegate graph exposure --plan tfplan.json --resource aws_ecs_service.admin
changegate graph visualize --plan tfplan.json --view exposure --resource aws_ecs_service.admin --out exposure.html
changegate attack-paths --plan tfplan.json --to-sensitive-data
changegate attack-paths visualize --plan tfplan.json --out attack-paths.html
changegate review github --report changegate.json --comment --annotations
changegate review gitlab --report changegate.json --comment
changegate context aws snapshot --out .changegate/aws-context.json --collect
changegate test examples/risk-tests
```

These commands reuse the same deterministic scan engine. The default path remains local and credential-free; AWS cloud context is opt-in and produces redacted offline snapshots. See [Review Intelligence](docs/review-intelligence.md), [Security Impact Statement](docs/security-impact-statement.md), [Blast-Radius Graph](docs/graph.md), and [Attack Paths](docs/attack-paths.md).

## What It Catches

The built-in AWS rule pack currently includes 29 stable high-confidence rules, including:

* public administrative services and database exposure
* world-open security group ingress on admin and database ports
* production RDS replacement, disabled backups, and disabled deletion protection
* broad IAM admin, PassRole, assume-role, KMS decrypt, and Secrets Manager read paths
* public-to-sensitive datastore graph paths
* sensitive storage without encryption or logging
* private subnet routes to internet gateways
* transit/peering route expansion into sensitive networks

See the generated [rule reference](docs/rules/README.md) for the full list.

## Install

Release install:

```bash
export CHANGEGATE_VERSION=vX.Y.Z
curl -fsSL "https://raw.githubusercontent.com/Gabriel0110/changegate/${CHANGEGATE_VERSION}/scripts/install.sh" | bash
```

The installer verifies `checksums.txt` and refuses checksum mismatches. See [release verification](docs/release-verification.md) for Cosign, checksum, attestation, and SBOM verification.

Development build:

```bash
go build -o bin/changegate ./cmd/changegate
bin/changegate version
```

## Quickstart

Terraform:

```bash
terraform init
terraform plan -out=tfplan
terraform show -json tfplan > tfplan.json
changegate scan --plan tfplan.json
```

OpenTofu:

```bash
tofu init
tofu plan -out=tfplan
tofu show -json tfplan > tfplan.json
changegate scan --plan tfplan.json
```

Exit codes are stable:

| Exit code | Meaning |
| --- | --- |
| `0` | Deployment is allowed. |
| `1` | ChangeGate found a blocking risk. |
| `2` | Usage or flag error. |
| `3` | Input parsing error. |
| `4` | Policy/configuration error. |
| `5` | Cloud-context error. |
| `10` | Internal error. |

## Output Formats

Use console output locally:

```bash
changegate scan --plan tfplan.json
```

Generate machine-readable output:

```bash
changegate scan --plan tfplan.json --format json --out changegate.json
changegate scan --plan tfplan.json --format sarif --out changegate.sarif
changegate scan --plan tfplan.json --format markdown --out changegate.md
changegate graph path --plan tfplan.json --from aws_lb.admin --to aws_db_instance.customer --format mermaid --out graph-path.mmd
changegate graph export --plan tfplan.json --format dot --out graph.dot
```

Generate visual review artifacts:

```bash
changegate graph visualize --plan tfplan.json --out graph.html
changegate graph visualize --plan tfplan.json --view path --from aws_lb.admin --to aws_db_instance.customer --out path.html
changegate attack-paths visualize --plan tfplan.json --out attack-paths.html
changegate graph render --plan tfplan.json --view exposure --resource aws_ecs_service.admin --render-format svg --out exposure.svg
```

Archive audit evidence:

```bash
changegate scan --plan tfplan.json --audit-bundle changegate-audit.zip
```

See [output formats](docs/output-formats.md) and [audit evidence](docs/audit-compliance.md).

## GitHub Actions

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
          echo "${CHANGEGATE_INSTALL_DIR}" >> "${GITHUB_PATH}"

      - name: ChangeGate scan
        id: changegate
        working-directory: infra
        run: |
          status=0
          changegate scan --plan tfplan.json --format sarif --out changegate.sarif || status=$?
          changegate scan --plan tfplan.json --format github-step-summary --out "$GITHUB_STEP_SUMMARY" || true
          echo "exit_code=$status" >> "$GITHUB_OUTPUT"

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@4c50b6f6fd9dc6fe03111c2d045c8be2a724cce1 # v3.28.11
        with:
          sarif_file: infra/changegate.sarif

      - name: Enforce ChangeGate decision
        if: always() && steps.changegate.outputs.exit_code != '0'
        run: exit "${{ steps.changegate.outputs.exit_code }}"
```

See [GitHub Actions](docs/github-actions.md), [GitLab CI](docs/gitlab-ci.md), [Atlantis](docs/atlantis.md), and [Terraform Cloud/Enterprise](docs/terraform-cloud.md).

## Risk Tests

Platform teams can define deterministic risk test manifests for Terraform/OpenTofu module fixtures and run them with `changegate test`. Risk tests assert ChangeGate decisions, required or forbidden findings, attack paths, graph paths, risk movement, waiver state, and stable output snapshots. See [risk tests](docs/risk-tests.md).

ChangeGate also includes a sanitized example corpus that doubles as executable documentation:

```bash
changegate test examples/risk-tests
```

## Roll Out Safely

Adopt ChangeGate in phases:

1. Run in audit mode and collect evidence.
2. Create a baseline for existing risks.
3. Enforce only new findings with `--new-only`.
4. Add expiring waivers for accepted temporary exceptions.
5. Move from audit to warn to block once teams understand the signal.

```bash
changegate scan --plan tfplan.json --mode audit --audit-bundle changegate-audit.zip
changegate baseline create --plan tfplan.json --out .changegate/baseline.json
changegate scan --plan tfplan.json --baseline .changegate/baseline.json --new-only
```

See [audit rollout](docs/audit-rollout.md), [baselines](docs/baselines.md), and [waivers](docs/waivers.md).

## Configuration

ChangeGate works with no config, but `.changegate.yaml` can tune policy, modes, rule packs, waivers, baselines, custom docs links, custom YAML rules, and custom Rego policies.

```yaml
mode: block

thresholds:
  block:
    min_severity: high
    min_confidence: high

baseline:
  file: .changegate/baseline.json
  mode: new-findings-only

waivers:
  file: .changegate/waivers.yaml
  require_expiration: true
```

See [policy config](docs/policy-config.md), [config schema](docs/config-schema.md), and [custom policy](docs/custom-policy.md).

## Project Status

ChangeGate is pre-`v1.0` and ready for early adopters who can run it in audit or warning mode against real Terraform/OpenTofu plans. The public contract already includes stable exit codes, stable JSON/SARIF-oriented output, signed-release infrastructure, baselines, waivers, generated rule docs, and security reporting.

The next phase is real-world calibration: sanitized fixtures, false-positive reports, and rule tuning from audit-mode usage.

See the [roadmap](docs/roadmap.md).

## Documentation

Start here:

* [Start here](docs/start-here.md)
* [Five-minute quickstart](docs/quickstart.md)
* [Rule reference](docs/rules/README.md)
* [GitHub Actions](docs/github-actions.md)
* [CI adoption](docs/ci-adoption.md)
* [Troubleshooting](docs/troubleshooting.md)
* [FAQ](docs/faq.md)

Operators:

* [Audit rollout](docs/audit-rollout.md)
* [Baselines](docs/baselines.md)
* [Waivers](docs/waivers.md)
* [Cloud context](docs/cloud-context.md)
* [Security model](docs/security-model.md)
* [Release verification](docs/release-verification.md)

Contributors:

* [Contributing](CONTRIBUTING.md)
* [Architecture](docs/architecture.md)
* [Rule authoring](docs/rule-authoring.md)
* [Fixture contributions](docs/fixtures.md)
* [Governance](docs/governance.md)
* [Maintainer guide](docs/maintainer-guide.md)
* [RFC process](docs/rfcs.md)

Reference:

* [Product spec](docs/product-spec.md)
* [CLI contract](docs/cli-contract.md)
* [Decision model](docs/decision-model.md)
* [Security Impact Statement](docs/security-impact-statement.md)
* [Review Intelligence](docs/review-intelligence.md)
* [Performance and scale](docs/performance.md)
* [JSON report schema](schemas/changegate-report.schema.json)
* [Graph JSON schema](schemas/changegate-graph.schema.json)
* [OPA input schema](schemas/changegate-opa-input.schema.json)

## Contributing

Issues and pull requests are welcome. New rules need tests, redacted fixtures, remediation guidance, generated rule docs, and changelog entries when they affect default policy behavior.

Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request.

## Security

Please do not open public issues for suspected vulnerabilities. Use the private reporting process in [SECURITY.md](SECURITY.md).

## License

ChangeGate is released under the [MIT License](LICENSE).
