# CLI Contract

## Binary

The binary name is `changegate`.

The CLI must be installable and runnable as a single static binary.

## Core Workflow

```bash
changegate scan --plan tfplan.json
```

This command is the primary product path and must remain fast, deterministic, and offline by default.

## Core Commands

```bash
changegate scan --plan tfplan.json
changegate scan --plan tfplan.json --format json
changegate scan --plan tfplan.json --format sarif --out changegate.sarif
changegate scan --plan dev.json --plan prod.json --format markdown --out changegate.md
changegate scan --plan tfplan.json --policy .changegate.yaml
changegate scan --plan tfplan.json --mode block
changegate scan --plan tfplan.json --mode warn
changegate scan --plan tfplan.json --mode audit
changegate scan --plan tfplan.json --baseline .changegate/baseline.json --new-only
changegate scan --plan tfplan.json --cloud-context aws
changegate scan --plan tfplan.json --context-file .changegate/aws-context.json
changegate scan --plan tfplan.json --import-sarif checkov.sarif --import-trivy trivy.json
changegate scan --plan tfplan.json --audit-bundle changegate-audit.zip
changegate scan --plan tfplan.json --timeout 2m --max-findings 100 --changed-only
```

## Developer Commands

```bash
changegate doctor
changegate explain <finding-id>
changegate explain AWS_PUBLIC_ADMIN_SERVICE
changegate explain CHG-1234567890ABCDEF --report changegate.json
changegate explain AWS_PUBLIC_ADMIN_SERVICE --json
changegate rules list
changegate rules describe <rule-id>
changegate version
changegate version --json
changegate completion bash
changegate completion zsh
changegate completion fish
```

## Future CI and Governance Commands

```bash
changegate ci detect
changegate ci github --working-directory infra
changegate ci gitlab --working-directory infra
changegate ci install github --working-directory infra
changegate baseline create --plan tfplan.json --out .changegate/baseline.json
changegate baseline diff --baseline .changegate/baseline.json --plan tfplan.json
changegate waiver add --file .changegate/waivers.yaml --rule AWS_RULE --resource aws_resource.name --owner platform@example.com --reason "Accepted temporarily" --expires-at 2026-08-01
changegate waiver list --file .changegate/waivers.yaml
changegate waiver validate --file .changegate/waivers.yaml
changegate waiver prune --file .changegate/waivers.yaml
changegate waiver report --file .changegate/waivers.yaml --plan tfplan.json
changegate context aws identity
changegate context aws snapshot --out .changegate/aws-context.json
changegate context aws permissions-template
changegate context aws validate-permissions --context-file .changegate/aws-context.json
changegate policy validate .changegate.yaml
changegate policy test .changegate.yaml
changegate policy validate .changegate.yaml # validates custom_rules and rego files when configured
```

## Global Flags

| Flag | Values | Contract |
| --- | --- | --- |
| `--format` | `table`, `json`, `sarif`, `junit`, `markdown`, `github-step-summary`, `github-annotations`, `gitlab-code-quality`, `pr-comment`, `audit-bundle` | Select output format. `table` is the human console default. |
| `--out` | path | Write selected output to a file instead of stdout where supported. |
| `--policy` | path | Load `.changegate.yaml`-compatible configuration. |
| `--cache-dir` | path | Prepare cache directories for policy packs and cloud context. |
| `--mode` | `block`, `warn`, `audit` | Select enforcement behavior. |
| `--no-color` | boolean | Disable ANSI color. |
| `--quiet` | boolean | Suppress non-essential human output. |
| `--verbose` | boolean | Emit additional diagnostic detail without secrets. |
| `--debug` | boolean | Emit developer diagnostics without secrets or raw environment dumps. |

## Exit Codes

| Code | Meaning |
| --- | --- |
| `0` | Scan completed; deploy allowed. |
| `1` | Scan completed; deploy blocked by policy. |
| `2` | Invalid CLI usage or invalid arguments. |
| `3` | Input parsing error. |
| `4` | Policy or configuration error. |
| `5` | Cloud-context or authentication error. |
| `6` | Internal scanner error. |
| `7` | Unsupported plan, schema, or provider version. |

Exit code `1` is reserved for a completed policy block. Operational failures must use their specific non-`1` codes.

## Error Contract

All user-facing errors must include:

* A clear cause.
* A suggested fix when one is known.
* A stable exit code.

The CLI must never panic on user input.

When `--format json` is selected, success and failure output must be valid JSON.
