# Architecture

ChangeGate is organized around one path: read plan JSON, normalize it, build graph context, evaluate rules, evaluate policy, render deterministic output.

```mermaid
flowchart LR
  "Terraform/OpenTofu plan JSON" --> "Plan loader"
  "Plan loader" --> "Normalized model"
  "Normalized model" --> "Graph builder"
  "Normalized model" --> "Rule runner"
  "Graph builder" --> "Rule runner"
  "Rule runner" --> "Findings"
  "External scanner imports" --> "Findings"
  "Cloud context snapshot" --> "Findings"
  "Findings" --> "Policy evaluator"
  "Baseline and waivers" --> "Policy evaluator"
  "Policy evaluator" --> "Scan report"
  "Scan report" --> "Report renderers"
  "Scan report" --> "Impact statement"
```

## Packages

| Package | Role |
| --- | --- |
| `internal/input/terraform` | Terraform/OpenTofu JSON ingestion and redaction. |
| `internal/model` | Provider-neutral plan, finding, evidence, policy, and decision types. |
| `internal/graph` | Resource relationship graph, Graph v2 classification, exposure, path, and blast-radius queries. |
| `internal/rules` | Built-in rule registry, metadata, runner, and AWS rules. |
| `internal/policy` | User-facing `.changegate.yaml` loading and validation. |
| `internal/custompolicy` | YAML and OPA/Rego custom policy support. |
| `internal/baseline` | Existing-risk baseline files and diffs. |
| `internal/waiver` | Reviewed, expiring exception governance. |
| `internal/output` | Console, JSON, SARIF, JUnit, Markdown, PR, GitLab, and audit-bundle rendering. |
| `internal/impact` | Canonical Security Impact Statement model built from scan reports. |
| `internal/cli` | Cobra command surface and user-facing error handling. |

## Determinism

Reports must be stable for the same inputs. Sorting is required for findings, rules, graph edges, archive members, and generated documentation.

## Security Boundaries

The default scan path is offline. Optional cloud context is file-based. Custom Rego rejects network/runtime builtins and runs with timeout and input-size limits.
