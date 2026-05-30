# ChangeGate Review Intelligence

Review Intelligence is the next ChangeGate feature track. It turns the existing plan parser, graph engine, policy decisions, waivers, baselines, remediation, and audit bundles into a production-grade infrastructure change review experience.

The feature set is experimental while it is being implemented. Existing `changegate scan` behavior remains stable unless a later release explicitly documents a backward-compatible extension or a new opt-in flag.

## Goals

Review Intelligence focuses on six capabilities:

1. Security Impact Statement and PR/MR review bot.
2. Blast-Radius Graph v2.
3. AWS Cloud Context Snapshot Collector.
4. Attack Path v1.
5. Risk Tests for Terraform modules.
6. Audit-ready evidence that ties findings, graph paths, waivers, baselines, and remediation together.

The HCP Terraform run task adapter is intentionally deferred. It remains planned, but it is out of scope until the core Review Intelligence features are production-ready.

## User Experience

The final workflow should let teams answer these questions from a pull request or CI run:

* What changed?
* What became public or reachable?
* Which workloads and data assets are in the blast radius?
* Which risks are new, existing, resolved, worsened, or waived?
* Which graph or attack paths justify the decision?
* What should the author or reviewer do next?

## Planned Commands

The active implementation cycle targets these commands:

```bash
changegate impact --plan tfplan.json --format markdown
changegate impact --plan tfplan.json --format json

changegate graph summary --plan tfplan.json
changegate graph path --plan tfplan.json --from aws_lb.admin --to aws_db_instance.customer
changegate graph exposure --plan tfplan.json --resource aws_ecs_service.admin
changegate graph export --plan tfplan.json --format json

changegate attack-paths --plan tfplan.json
changegate attack-paths --plan tfplan.json --principal aws_iam_role.github_actions
changegate attack-paths --plan tfplan.json --to-sensitive-data

changegate context aws snapshot --out .changegate/aws-context.json --collect

changegate review github --report changegate.json --comment --annotations
changegate review gitlab --report changegate.json --comment

changegate test
changegate test ./changegate-tests
```

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
  block_high_confidence: true
```

These settings are feature toggles and output controls for the new commands. They do not change existing `changegate scan` behavior during Tranche 0.

## Implementation Plan

The full tranche plan is maintained in [Review Intelligence implementation plan](review-intelligence-plan.md).
