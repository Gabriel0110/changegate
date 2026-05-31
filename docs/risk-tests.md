# Risk Tests

Risk tests let Terraform/OpenTofu module authors keep security behavior under regression test. A risk test points ChangeGate at a saved plan fixture and declares the deployment decision, findings, attack paths, graph paths, baseline movement, waiver state, or snapshot output that must remain true.

The `changegate test` command is planned in the next tranche. This page documents the manifest contract implemented by the risk test engine.

## Manifest

Create a manifest named `changegate-test.yaml`, `changegate-tests.yaml`, or `*.changegate-test.yaml`.

```yaml
version: 1
tests:
  - name: public_admin_service_should_block
    plan: fixtures/public-admin-service.json
    config: fixtures/changegate.yaml
    expect:
      decision: block
      findings:
        include:
          - AWS_PUBLIC_ADMIN_SERVICE
        exclude:
          - AWS_PUBLIC_RDS_INSTANCE
      attack_paths:
        include:
          - public_to_sensitive_data
      graph_paths:
        include:
          - aws_lb.admin -> aws_db_instance.customer
      severity_count:
        critical: 1
      risk_movement:
        new_high: 1
      waivers:
        not_applied:
          - AWS_PUBLIC_ADMIN_SERVICE
      snapshot: snapshots/public-admin-service.json

  - name: public_web_alb_should_pass
    plan: fixtures/public-web-alb.json
    expect:
      decision: allow
      findings:
        exclude:
          - AWS_PUBLIC_ADMIN_SERVICE
```

Paths are resolved relative to the manifest file. The parser is strict: unknown fields fail validation so test files do not silently drift.

## Assertions

Supported assertions:

| Field | Meaning |
| --- | --- |
| `decision` | Expected deployment decision: `allow`, `warn`, or `block`. |
| `findings.include` | Rule IDs that must appear in the scan report. |
| `findings.exclude` | Rule IDs that must not appear in the scan report. |
| `severity_count` | Exact finding count by severity. |
| `attack_paths.include` / `exclude` | Attack path types such as `public_to_sensitive_data` or `iam_privilege_escalation`. |
| `graph_paths.include` / `exclude` | Graph path fragments that must or must not appear in graph path evidence. |
| `risk_movement` | Exact baseline movement counters, including `new_high`, `existing_worsened`, and waiver counters. |
| `waivers.applied` | Rule IDs that must have an active waiver suppression. |
| `waivers.not_applied` | Rule IDs that must not have an active waiver suppression. |
| `snapshot` | Stable JSON snapshot path for the full scan report. |

## Discovery

Directory discovery recursively finds:

* `changegate-test.yaml`
* `changegate-test.yml`
* `changegate-tests.yaml`
* `changegate-tests.yml`
* `.changegate-test.yaml`
* `.changegate-tests.yaml`
* `*.changegate-test.yaml`
* `*.changegate-test.yml`

Discovery skips `.git`, `.terraform`, `node_modules`, and `vendor`.
