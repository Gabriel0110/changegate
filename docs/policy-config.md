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
    AWS_PUBLIC_RDS_INSTANCE: https://example.com/security/rds-public-access
    default: https://example.com/security/changegate
```

## Compliance Metadata

```yaml
compliance:
  mappings:
    ORG_QUEUE_REVIEW:
      frameworks:
        soc2:
          - CC8.1
        iso_27001:
          - A.5.8
```

Organization mappings can reference built-in or custom rule IDs. They are non-enforcing metadata used in JSON reports and audit bundles; they do not change allow, warn, or block decisions.

## Sensitive Assets

ChangeGate automatically treats common AWS data stores, secrets, and KMS keys as sensitive graph assets. You can add organization-specific resources without changing code:

```yaml
sensitive_assets:
  resource_addresses:
    - custom_service.customer_ledger
  resource_types:
    - aws_backup_vault
  name_contains:
    - cardholder
  tags:
    classification: restricted
    data_domain: regulated
```

The selectors are additive. A resource is classified as a sensitive data asset when any selector matches:

- `resource_addresses` matches a Terraform/OpenTofu resource address exactly.
- `resource_types` matches the Terraform/OpenTofu resource type exactly.
- `name_contains` matches a case-insensitive substring in the resource address, name, or type.
- `tags` matches a tag key and value; an empty value matches the presence of the tag key.

Built-in sensitivity tag defaults also classify otherwise-unknown resources when tags such as `data=sensitive`, `classification=restricted`, `sensitivity=confidential`, or `confidentiality=pii` are present. Generic environment tags such as `env=prod` do not make a resource sensitive by themselves.

## Review Intelligence

Review Intelligence settings control Security Impact Statements, PR/MR review output, and attack path enforcement. Attack paths are first-class scan findings by default, so they participate in policy thresholds, baselines, waivers, and audit bundles.

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

The complete field reference is in [config schema](config-schema.md).
