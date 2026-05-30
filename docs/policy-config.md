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

The complete field reference is in [config schema](config-schema.md).
