# Review Scenario Demos

These demos are copy-pasteable ChangeGate scenarios built from sanitized plan fixtures. They are useful when evaluating output shape before wiring ChangeGate into a real repository.

## Run All Scenarios

From the repository root:

```bash
changegate scan --plan examples/risk-tests/fixtures/public-web-alb.json
changegate scan --plan examples/risk-tests/fixtures/lambda-url-secret.json --context-file examples/risk-tests/contexts/lambda-url-secret.json
changegate scan --plan examples/risk-tests/fixtures/passrole-lambda-update.json
changegate scan --plan examples/risk-tests/fixtures/public-rds-prod.json --baseline examples/risk-tests/baselines/public-rds-prod.json --new-only
changegate scan --plan examples/risk-tests/fixtures/public-rds-staging.json --policy examples/risk-tests/policies/staging-waiver.yaml
changegate scan --plan examples/risk-tests/fixtures/public-rds-prod.json --policy examples/risk-tests/policies/staging-waiver.yaml
```

Blocking scenarios intentionally exit with code `1`.

## Scenarios

| Scenario                    | Plan fixture                                                                      | Expected decision | Generated artifacts                                                                                                                                                                              |
| --------------------------- | --------------------------------------------------------------------------------- | ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Expected public web ALB     | [public-web-alb.json](../risk-tests/fixtures/public-web-alb.json)                 | `ALLOW`           | [scan](outputs/expected-public-web-scan.md), [PR comment](outputs/expected-public-web-pr-comment.md)                                                                                             |
| Public Lambda URL to secret | [lambda-url-secret.json](../risk-tests/fixtures/lambda-url-secret.json)           | `BLOCK`           | [scan](outputs/lambda-secret-scan.md), [PR comment](outputs/lambda-secret-pr-comment.md), [attack paths](outputs/lambda-secret-attack-paths.md), [HTML](outputs/lambda-secret-attack-paths.html) |
| IAM PassRole escalation     | [passrole-lambda-update.json](../risk-tests/fixtures/passrole-lambda-update.json) | `BLOCK`           | [scan](outputs/iam-passrole-scan.md), [PR comment](outputs/iam-passrole-pr-comment.md), [attack paths](outputs/iam-passrole-attack-paths.md), [HTML](outputs/iam-passrole-attack-paths.html)     |
| Baseline new-risk-only flow | [public-rds-prod.json](../risk-tests/fixtures/public-rds-prod.json)               | `ALLOW`           | [scan](outputs/baseline-new-only-scan.md)                                                                                                                                                        |
| Staging waiver accepted     | [public-rds-staging.json](../risk-tests/fixtures/public-rds-staging.json)         | `ALLOW`           | [scan](outputs/waiver-staging-scan.md)                                                                                                                                                           |
| Production waiver rejected  | [public-rds-prod.json](../risk-tests/fixtures/public-rds-prod.json)               | `BLOCK`           | [scan](outputs/waiver-production-rejected-scan.md)                                                                                                                                               |

## Generate The Same Outputs

```bash
changegate scan --plan examples/risk-tests/fixtures/public-web-alb.json --format markdown --out examples/demo-review-scenarios/outputs/expected-public-web-scan.md
changegate scan --plan examples/risk-tests/fixtures/public-web-alb.json --format pr-comment --out examples/demo-review-scenarios/outputs/expected-public-web-pr-comment.md

changegate scan --plan examples/risk-tests/fixtures/lambda-url-secret.json --context-file examples/risk-tests/contexts/lambda-url-secret.json --format markdown --out examples/demo-review-scenarios/outputs/lambda-secret-scan.md || true
changegate scan --plan examples/risk-tests/fixtures/lambda-url-secret.json --context-file examples/risk-tests/contexts/lambda-url-secret.json --format pr-comment --out examples/demo-review-scenarios/outputs/lambda-secret-pr-comment.md || true
changegate attack-paths --plan examples/risk-tests/fixtures/lambda-url-secret.json --context-file examples/risk-tests/contexts/lambda-url-secret.json --format markdown --out examples/demo-review-scenarios/outputs/lambda-secret-attack-paths.md
changegate attack-paths visualize --plan examples/risk-tests/fixtures/lambda-url-secret.json --context-file examples/risk-tests/contexts/lambda-url-secret.json --out examples/demo-review-scenarios/outputs/lambda-secret-attack-paths.html

changegate scan --plan examples/risk-tests/fixtures/passrole-lambda-update.json --format markdown --out examples/demo-review-scenarios/outputs/iam-passrole-scan.md || true
changegate scan --plan examples/risk-tests/fixtures/passrole-lambda-update.json --format pr-comment --out examples/demo-review-scenarios/outputs/iam-passrole-pr-comment.md || true
changegate attack-paths --plan examples/risk-tests/fixtures/passrole-lambda-update.json --format markdown --out examples/demo-review-scenarios/outputs/iam-passrole-attack-paths.md
changegate attack-paths visualize --plan examples/risk-tests/fixtures/passrole-lambda-update.json --out examples/demo-review-scenarios/outputs/iam-passrole-attack-paths.html

changegate scan --plan examples/risk-tests/fixtures/public-rds-prod.json --baseline examples/risk-tests/baselines/public-rds-prod.json --new-only --format markdown --out examples/demo-review-scenarios/outputs/baseline-new-only-scan.md
changegate scan --plan examples/risk-tests/fixtures/public-rds-staging.json --policy examples/risk-tests/policies/staging-waiver.yaml --format markdown --out examples/demo-review-scenarios/outputs/waiver-staging-scan.md
changegate scan --plan examples/risk-tests/fixtures/public-rds-prod.json --policy examples/risk-tests/policies/staging-waiver.yaml --format markdown --out examples/demo-review-scenarios/outputs/waiver-production-rejected-scan.md || true
```
