# Policy Config Guide

ChangeGate policy files are YAML and are usually named `.changegate.yaml`.

Minimal policy:

```yaml
version: 1
mode: block
policy_packs:
  - aws-core
  - aws-public-exposure
  - aws-iam-escalation
```

## Thresholds

```yaml
decision:
  block_on:
    min_severity: high
    min_confidence: high
  warn_on:
    min_severity: medium
    min_confidence: medium
```

## Scope

```yaml
scope:
  changed_resources_only: true
```

This suppresses findings outside the resources changed by the plan for enforcement.

## Baselines and Waivers

```yaml
baseline:
  file: .changegate/baseline.json
  mode: new-risk-only
  max_age_days: 30
  require_expiration: true

waivers:
  file: .changegate/waivers.yaml
  require_expiration: true
  max_duration_days: 90
  fail_expired: true
```

## Custom Documentation Links

```yaml
docs:
  links:
    AWS_PUBLIC_RDS_INSTANCE: https://internal.example.com/rds-public-access
    default: https://internal.example.com/changegate
```

## Review Intelligence

Review Intelligence settings control upcoming Security Impact Statement, PR/MR review, and attack path commands. They are accepted by the strict policy schema now, but they do not change existing `changegate scan` behavior.

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

The complete field reference is in [config schema](config-schema.md).
