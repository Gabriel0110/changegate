# Security Impact Statement

The Security Impact Statement is the review-grade summary behind `changegate impact`, PR/MR comments, and audit bundles. It turns scan findings into a deploy decision, risk movement, graph evidence, attack paths, waiver state, and required human review context.

Use it when reviewers need to understand what changed without reading the full JSON scan report.

## Commands

```bash
changegate impact --plan tfplan.json --format markdown
changegate impact --plan tfplan.json --format json --out impact.json
changegate impact --plan tfplan.json --baseline .changegate/baseline.json --new-only
changegate impact --plan tfplan.json --context-file .changegate/aws-context.json
changegate impact --plan tfplan.json --audit-bundle impact-audit.zip
```

`changegate impact` accepts the same core inputs as `changegate scan`: policy config, baselines, waivers, cloud-context files, external scanner imports, multiple plan files, and timeouts. The command returns the same enforcement exit code as the underlying scan decision.

## What It Contains

The JSON statement has schema version `1` and includes:

| Field | Meaning |
| --- | --- |
| `decision` | Final `allow`, `warn`, or `block` decision. |
| `decision_reasons` | Policy reasons that explain the decision. |
| `summary` | Counts for changed resources, public entrypoints, sensitive assets, IAM changes, network paths, and data paths. |
| `risk_movement` | New, resolved, existing, worsened, improved, and waived risk counts. |
| `top_findings` | Highest-priority redacted findings after policy, baseline, and waiver handling. |
| `top_graph_paths` | Graph paths promoted into review evidence. |
| `attack_paths` | Public-to-sensitive and IAM escalation paths promoted into review evidence. |
| `waivers` | Active, expired, and total waiver counts. |
| `baseline` | Existing and new finding counts. |
| `ownership` | Owner hints inferred from tags, remediation metadata, or finding context. |
| `required_reviewers` | Deterministic review requirements derived from the decision and high-risk findings. |
| `section_ids` | Stable anchors for downstream renderers and comments. |
| `source` | Source scan report, plan, and graph summary metadata. |
| `diagnostics` | Non-fatal warnings from parsing, imports, cloud context, or collection coverage. |

## Markdown Output

Markdown output is meant for pull requests, merge requests, approval tickets, and release notes:

```bash
changegate impact --plan tfplan.json --format markdown --out impact.md
```

It summarizes:

* deploy decision and whether review is required
* public entrypoints, sensitive assets, IAM changes, network changes, and data changes
* risk movement against the configured baseline
* top blast-radius graph paths
* attack paths
* top findings
* required review routing

For GitHub/GitLab comments, prefer `changegate review github` or `changegate review gitlab`; those commands use the same statement model but render a sticky provider-specific comment with size limits and artifact links.

## Audit Bundle

`changegate impact --audit-bundle impact-audit.zip` writes a deterministic impact archive:

* `changegate-impact/impact-statement.json`
* `changegate-impact/impact-statement.md`
* `changegate-impact/scan-report.json`

For full CI evidence, prefer `changegate scan --audit-bundle changegate-audit.zip`, which includes the impact statement plus graph, attack-path, cloud-context summary, waiver, baseline, compliance, and review-comment evidence.

## Redaction and Stability

The statement uses already-normalized findings and redacted evidence. Sensitive evidence values are replaced before JSON or Markdown rendering. The statement is deterministic for the same scan report, limits, and generation timestamp.

Use `--max-findings` and `--max-paths` to cap review output in large repositories:

```bash
changegate impact --plan tfplan.json --format markdown --max-findings 10 --max-paths 5
```
