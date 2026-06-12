# ChangeGate Review Intelligence

Review Intelligence turns plan analysis, graph evidence, policy decisions, waivers, baselines, remediation, and audit bundles into an infrastructure change review workflow.

The workflow is local CLI functionality. `changegate scan` remains the core gate, and the review commands reuse the same deterministic report model.

## Capabilities

Review Intelligence focuses on six capabilities:

1. Security Impact Statement and PR/MR review bot.
2. Blast-Radius Graph v2.
3. AWS Cloud Context Snapshot Collector.
4. Attack Paths v2.
5. Risk Tests for Terraform modules.
6. Audit-ready evidence that ties findings, graph paths, waivers, baselines, and remediation together.

## User Experience

The workflow answers these questions from a pull request or CI run:

- What changed?
- What became public or reachable?
- Which workloads and data assets are in the blast radius?
- Which risks are new, existing, resolved, worsened, or waived?
- Which graph or attack paths justify the decision?
- What should the author or reviewer do next?

## Commands

The primary commands are:

```bash
changegate impact --plan tfplan.json --format markdown
changegate impact --plan tfplan.json --format json
changegate impact --plan tfplan.json --baseline .changegate/baseline.json --new-only
changegate impact --plan tfplan.json --audit-bundle impact-audit.zip
```

`changegate impact` reuses the same scan engine as `changegate scan`, including policy config, baselines, waivers, cloud context files, external scanner imports, and multi-plan input. Markdown is intended for pull requests and approval workflows; JSON is the stable machine contract.

See [Security Impact Statement](security-impact-statement.md) for the statement contract and output behavior.

Blast-Radius Graph v2 is available through `changegate graph`. It classifies public entrypoints, workloads, data stores, secrets, KMS keys, principals, policies, and network boundaries, then exposes deterministic path, exposure, blast-radius, sensitive-asset, and changed-boundary-crossing queries. See [Blast-Radius Graph](graph.md).

```bash
changegate graph summary --plan tfplan.json
changegate graph path --plan tfplan.json --from aws_lb.admin --to aws_db_instance.customer
changegate graph exposure --plan tfplan.json --resource aws_ecs_service.admin
changegate graph export --plan tfplan.json --format json
changegate graph visualize --plan tfplan.json --view exposure --resource aws_ecs_service.admin --out exposure.html
```

Graph visualizations are available as DOT, Mermaid, self-contained interactive HTML, and optional Graphviz-rendered SVG/PNG/PDF artifacts. Use HTML for review links and CI artifacts when reviewers need to understand blast radius without opening JSON.

PR/MR review output is built from the Security Impact Statement model. It produces GitHub/GitLab-compatible Markdown with one stable hidden marker, compact deploy-decision summary, risk movement, top findings, graph paths, attack paths, waiver state, ownership hints, artifact links, size-limit compaction, and redaction-safe finding details.

GitHub PR review publishing is available through `changegate review github`. It can consume a saved scan JSON report or build the report directly from plan input, update one sticky pull request comment, emit GitHub Actions workflow annotations, and write the same review summary to `GITHUB_STEP_SUMMARY`.

```bash
changegate review github --report changegate.json --comment
changegate review github --report changegate.json --annotations
changegate review github --plan tfplan.json --comment --annotations
changegate review github --report changegate.json --comment --dry-run --repo owner/repo --pr 123
```

GitLab MR review publishing is available through `changegate review gitlab`. It can consume a saved scan JSON report or build the report directly from plan input, update one sticky merge request note, and include GitLab Code Quality artifact links.

```bash
changegate review gitlab --report changegate.json --comment
changegate review gitlab --plan tfplan.json --comment
changegate review gitlab --report changegate.json --comment --dry-run --project 123 --merge-request 456
```

Attack path inspection is available through `changegate attack-paths`. It detects deterministic v2 public-to-sensitive-data and IAM privilege-escalation paths without running deployment enforcement.

```bash
changegate attack-paths --plan tfplan.json
changegate attack-paths --plan tfplan.json --principal aws_iam_role.github_actions
changegate attack-paths --plan tfplan.json --to-sensitive-data
changegate attack-paths --plan tfplan.json --format json
changegate attack-paths visualize --plan tfplan.json --out attack-paths.html
```

AWS cloud context collection and risk tests are available:

```bash
changegate context aws snapshot --out .changegate/aws-context.json --collect=all
changegate test
changegate test ./changegate-tests
```

See [Attack Paths](attack-paths.md) for the JSON schema, Markdown rendering behavior, detector behavior, and policy eligibility rules.
See [Cloud Context](cloud-context.md) for AWS snapshot collection and [Risk Tests](risk-tests.md) for module regression manifests.

## Configuration

Review Intelligence configuration lives in `.changegate.yaml` and is accepted by the strict policy schema.

```yaml
review:
  enabled: true
  max_comment_findings: 10
  max_graph_paths: 5
  sticky_comment_marker: "<!-- changegate-review -->"

impact:
  include_existing_risks: true
  include_resolved_risks: true
  include_waivers: true

attack_paths:
  enabled: true
  block:
    - type: public_to_sensitive_data
      min_confidence: high
    - type: iam_privilege_escalation
      min_confidence: high
  warn:
    - type: public_to_sensitive_data
      min_confidence: medium
    - type: iam_privilege_escalation
      min_confidence: medium
```

These settings are output controls and deterministic enforcement thresholds. Attack path findings emitted during `changegate scan` use normal policy, baseline, waiver, and audit-bundle behavior.
