# Risk Tests

Risk tests let Terraform/OpenTofu module authors keep security behavior under regression test. A risk test points ChangeGate at a saved plan fixture and declares the deployment decision, findings, attack paths, graph paths, baseline movement, waiver state, or snapshot output that must remain true.

Run risk tests locally or in CI:

```bash
changegate test
changegate test ./changegate-tests
changegate test examples/risk-tests
changegate test --format json
changegate test --format junit --out changegate-tests.xml
changegate test --junit changegate-tests.xml
changegate test --update
```

The command exits `0` when all tests pass and exits non-zero when any test fails, errors, or cannot be discovered.

## Manifest

Create a manifest named `changegate-test.yaml`, `changegate-tests.yaml`, or `*.changegate-test.yaml`.

```yaml
version: 1
tests:
  - name: public_admin_service_should_block
    plan: fixtures/public-admin-service.json
    config: fixtures/changegate.yaml
    baseline: fixtures/baseline.json
    new_only: true
    context_file: fixtures/aws-context.json
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

The repository includes a sanitized runnable corpus at [examples/risk-tests](../examples/risk-tests). It covers expected public edges, public admin exposure, public-to-sensitive graph paths, IAM escalation paths, baseline movement, waiver scoping, and cloud-context severity changes.

For copy-pasteable review examples built from the same sanitized fixtures, see [review scenario demos](../examples/demo-review-scenarios).

## Case Fields

Each test case supports:

| Field          | Required | Meaning                                                                                                                                     |
| -------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| `name`         | yes      | Stable test name shown in CLI, JSON, and JUnit output.                                                                                      |
| `plan`         | yes      | Terraform/OpenTofu plan JSON fixture.                                                                                                       |
| `config`       | no       | ChangeGate policy file for this test. Policy-local `baseline.file` and `waivers.file` references are resolved relative to that policy file. |
| `baseline`     | no       | Baseline file passed as `--baseline` for this test.                                                                                         |
| `new_only`     | no       | Enables `--new-only`; requires `baseline`.                                                                                                  |
| `context_file` | no       | Offline cloud context snapshot passed as `--context-file`.                                                                                  |
| `expect`       | yes      | Assertions for the scan result.                                                                                                             |

## Output

Default output is concise and developer-oriented:

```text
PASS public_web_alb_should_pass
FAIL public_admin_service_should_block
  decision: expected decision "block", got "warn"
  findings.include: expected finding AWS_PUBLIC_ADMIN_SERVICE to be present

Risk tests: failed
Manifests: 1
Tests: 1 passed, 1 failed, 0 errors
```

Use `--format json` for machine-readable CI output. Use `--format junit --out changegate-tests.xml`, or keep console output and also write JUnit with `--junit changegate-tests.xml`.

`--update` updates snapshot files only. It does not rewrite expected decisions, findings, attack path expectations, or any other assertions.

## Assertions

Supported assertions:

| Field                              | Meaning                                                                                           |
| ---------------------------------- | ------------------------------------------------------------------------------------------------- |
| `decision`                         | Expected deployment decision: `allow`, `warn`, or `block`.                                        |
| `findings.include`                 | Rule IDs that must appear in the scan report.                                                     |
| `findings.exclude`                 | Rule IDs that must not appear in the scan report.                                                 |
| `severity_count`                   | Exact finding count by severity.                                                                  |
| `attack_paths.include` / `exclude` | Attack path types such as `public_to_sensitive_data` or `iam_privilege_escalation`.               |
| `graph_paths.include` / `exclude`  | Graph path fragments that must or must not appear in graph path evidence.                         |
| `risk_movement`                    | Exact baseline movement counters, including `new_high`, `existing_worsened`, and waiver counters. |
| `waivers.applied`                  | Rule IDs that must have an active waiver suppression.                                             |
| `waivers.not_applied`              | Rule IDs that must not have an active waiver suppression.                                         |
| `snapshot`                         | Stable JSON snapshot path for the full scan report.                                               |

## Discovery

Directory discovery recursively finds:

- `changegate-test.yaml`
- `changegate-test.yml`
- `changegate-tests.yaml`
- `changegate-tests.yml`
- `.changegate-test.yaml`
- `.changegate-tests.yaml`
- `*.changegate-test.yaml`
- `*.changegate-test.yml`

Discovery skips `.git`, `.terraform`, `node_modules`, and `vendor`.
