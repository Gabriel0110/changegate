# Config Schema

The default policy file is `.changegate.yaml`. ChangeGate decodes this file with strict field checking, so unknown fields fail validation instead of being silently ignored.

This is the human-readable schema contract for policy version `1`.

## Example

```yaml
version: 1
mode: block

decision:
  block_on:
    min_severity: high
    min_confidence: high
  warn_on:
    min_severity: medium
    min_confidence: medium

policy_packs:
  - aws-core
  - aws-public-exposure
  - aws-iam-escalation

policy_pack_versions:
  aws-core: 0.1.0
  aws-public-exposure: 0.1.0
  aws-iam-escalation: 0.1.0

rules:
  disabled:
    - AWS_PUBLIC_EKS_ENDPOINT_PROD

overrides:
  AWS_PUBLIC_RDS_INSTANCE:
    severity: high
    confidence: high
    reason: "Keep public database findings as blocking in production."

environments:
  production:
    decision:
      block_on:
        min_severity: high
        min_confidence: high

branches:
  main:
    decision:
      warn_on:
        min_severity: medium
        min_confidence: medium

scope:
  changed_resources_only: true

baseline:
  mode: new-risk-only
  fingerprints: []
  max_age_days: 30
  require_expiration: true

waivers:
  require_expiration: true
  max_duration_days: 90
  fail_expired: true

docs:
  links:
    default: <your-changegate-security-doc-url>
    public_exposure: <your-public-exposure-doc-url>
    AWS_PUBLIC_ADMIN_SERVICE: <your-admin-service-doc-url>

compliance:
  mappings:
    ORG_QUEUE_REVIEW:
      frameworks:
        soc2:
          - CC8.1
        iso_27001:
          - A.5.8

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

## Fields

| Field                                      | Type         | Required | Contract                                                                                                                                                  |
| ------------------------------------------ | ------------ | -------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `version`                                  | integer      | no       | Config schema version. Current value is `1`; omitted also means version `1`.                                                                              |
| `mode`                                     | enum         | no       | One of `block`, `warn`, or `audit`. Defaults to `block`.                                                                                                  |
| `decision.block_on.min_severity`           | enum         | no       | Minimum severity eligible to block. Defaults to `high`.                                                                                                   |
| `decision.block_on.min_confidence`         | enum         | no       | Minimum confidence eligible to block. Defaults to `high`.                                                                                                 |
| `decision.warn_on.min_severity`            | enum         | no       | Minimum severity eligible to warn. Defaults to `medium`.                                                                                                  |
| `decision.warn_on.min_confidence`          | enum         | no       | Minimum confidence eligible to warn. Defaults to `medium`.                                                                                                |
| `policy_packs`                             | string array | no       | Built-in policy packs to enable. Omitted enables the default stable packs.                                                                                |
| `policy_pack_versions`                     | map          | no       | Optional built-in policy pack version pins. Validation fails on mismatch.                                                                                 |
| `policy_pack_signing.require_signed`       | boolean      | no       | Remote policy pack signing is not supported by the local policy loader. Setting this to `true` fails validation.                                          |
| `policy_pack_signing.trusted_keys`         | string array | no       | Trusted key identifiers for remote policy pack signing. This field is accepted for schema compatibility but is not used by the local policy loader.       |
| `rules.enabled`                            | string array | no       | Explicit built-in rule IDs to enable.                                                                                                                     |
| `rules.disabled`                           | string array | no       | Built-in rule IDs to disable.                                                                                                                             |
| `overrides.<rule_id>.severity`             | enum         | no       | Override severity for a known rule.                                                                                                                       |
| `overrides.<rule_id>.confidence`           | enum         | no       | Override confidence for a known rule.                                                                                                                     |
| `overrides.<rule_id>.reason`               | string       | no       | Review note explaining the override.                                                                                                                      |
| `environments.<name>.decision`             | object       | no       | Environment-specific thresholds selected from detected plan environment.                                                                                  |
| `branches.<name>.decision`                 | object       | no       | Branch-specific thresholds selected from the `--branch` scan flag.                                                                                        |
| `scope.changed_resources_only`             | boolean      | no       | Only enforce findings on resources changed by the plan.                                                                                                   |
| `baseline.file`                            | string       | no       | Baseline file path.                                                                                                                                       |
| `baseline.mode`                            | enum         | no       | `new-risk-only` or `new-findings-only`; both suppress matching existing findings.                                                                         |
| `baseline.fingerprints`                    | string array | no       | Inline existing-risk fingerprints. File-based baselines are preferred.                                                                                    |
| `baseline.max_age_days`                    | integer      | no       | Warn when a loaded baseline is older than this many days.                                                                                                 |
| `baseline.require_expiration`              | boolean      | no       | Warn when a loaded baseline has no `expires_at` value.                                                                                                    |
| `waivers.file`                             | string       | no       | Waiver file path.                                                                                                                                         |
| `waivers.require_expiration`               | boolean      | no       | Require waiver expiration dates. Defaults to `true`.                                                                                                      |
| `waivers.max_duration_days`                | integer      | no       | Maximum allowed waiver duration.                                                                                                                          |
| `waivers.fail_expired`                     | boolean      | no       | Fail scans when the waiver file contains expired waivers.                                                                                                 |
| `custom_rules.files`                       | string array | no       | Declarative YAML rule files or globs, resolved relative to this policy file.                                                                              |
| `custom_rules.required`                    | boolean      | no       | Fail validation if a configured custom rule glob matches no files.                                                                                        |
| `custom_rules.max_file_size`               | integer      | no       | Maximum custom YAML rule file size in bytes. Defaults to 1 MiB.                                                                                           |
| `rego.files`                               | string array | no       | Optional OPA/Rego module files or globs. Rego is disabled when omitted.                                                                                   |
| `rego.query`                               | string       | no       | Rego query to evaluate. Defaults to `data.changegate.findings`.                                                                                           |
| `rego.timeout`                             | duration     | no       | Maximum Rego evaluation time. Defaults to `250ms`; maximum `5s`.                                                                                          |
| `rego.max_input_bytes`                     | integer      | no       | Maximum serialized Rego input size. Defaults to 5 MiB.                                                                                                    |
| `docs.links`                               | map          | no       | Documentation links keyed by rule ID, risk category, provider, or `default`; added to remediation output.                                                 |
| `compliance.mappings.<rule_id>.frameworks` | map          | no       | Organization compliance mappings for built-in or custom rule IDs. These add to or override bundled rule-to-control metadata in reports and audit bundles. |
| `review.enabled`                           | boolean      | no       | Enables Review Intelligence PR/MR review features when those commands are used. Defaults to `true`. Existing `scan` behavior is unchanged.                |
| `review.max_comment_findings`              | integer      | no       | Maximum findings to show in the sticky PR/MR summary comment. Defaults to `10`; must be non-negative.                                                     |
| `review.max_graph_paths`                   | integer      | no       | Maximum graph or attack paths to include in review summaries. Defaults to `5`; must be non-negative.                                                      |
| `review.sticky_comment_marker`             | string       | no       | Hidden marker used to update one stable review comment instead of posting duplicates. Defaults to `<!-- changegate-review -->`.                           |
| `impact.include_existing_risks`            | boolean      | no       | Include unchanged baseline risks in Security Impact Statements. Defaults to `true`.                                                                       |
| `impact.include_resolved_risks`            | boolean      | no       | Include resolved baseline risks in Security Impact Statements. Defaults to `true`.                                                                        |
| `impact.include_waivers`                   | boolean      | no       | Include waiver state and waiver counts in Security Impact Statements. Defaults to `true`.                                                                 |
| `attack_paths.enabled`                     | boolean      | no       | Enables attack path detection for `scan`, Review Intelligence, impact statements, and attack-path commands. Defaults to `true`.                           |
| `attack_paths.block`                       | array        | no       | Attack path thresholds that become block-eligible findings. Defaults to high-confidence `public_to_sensitive_data` and `iam_privilege_escalation`.        |
| `attack_paths.warn`                        | array        | no       | Attack path thresholds that become warning-eligible findings. Defaults to medium-confidence `public_to_sensitive_data` and `iam_privilege_escalation`.    |
| `attack_paths.block[].type`                | enum         | no       | Attack path type. Supported values are `public_to_sensitive_data` and `iam_privilege_escalation`.                                                         |
| `attack_paths.block[].min_confidence`      | enum         | no       | Minimum confidence for the block threshold. Defaults to `high` when omitted.                                                                              |
| `attack_paths.warn[].type`                 | enum         | no       | Attack path type. Supported values are `public_to_sensitive_data` and `iam_privilege_escalation`.                                                         |
| `attack_paths.warn[].min_confidence`       | enum         | no       | Minimum confidence for the warning threshold. Defaults to `high` when omitted.                                                                            |

## Enum Values

Severity values:

```text
critical
high
medium
low
info
```

Confidence values:

```text
high
medium
low
unknown
```

Mode values:

```text
block
warn
audit
```

Baseline mode values:

```text
new-risk-only
new-findings-only
```
