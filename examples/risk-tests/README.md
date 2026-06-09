# ChangeGate Risk Test Corpus

This directory is a runnable, sanitized corpus for ChangeGate's differentiated behaviors.

Run it from the repository root:

```bash
changegate test examples/risk-tests
```

The fixtures are hand-written minimal Terraform plan JSON documents. They use only synthetic identifiers:

- account ID `123456789012`
- example ARNs and names
- no real domains
- no real public IPs
- only the attributes needed to prove each behavior

## What The Corpus Proves

| Fixture                                           | Behavior                                                                                      |
| ------------------------------------------------- | --------------------------------------------------------------------------------------------- |
| `public-web-alb.json`                             | Expected public web ALB is allowed when it carries explicit public-edge controls.             |
| `public-admin-alb.json`                           | Public admin service is blocked.                                                              |
| `public-alb-ecs-rds.json`                         | Public entrypoint to ECS to RDS creates a blocking public-to-sensitive-data attack path.      |
| `lambda-url-secret.json` + cloud context          | Public Lambda function URL reaching a secret is blocked through cloud-context graph evidence. |
| `passrole-lambda-update.json`                     | `iam:PassRole` plus Lambda code update is blocked as privilege escalation.                    |
| `assume-role-admin.json`                          | `sts:AssumeRole` to admin role is blocked.                                                    |
| `pathfinding-codebuild-passrole.json`             | Embedded pathfinding.cloud IAM escalation prerequisites are blocked for CodeBuild pass-role.  |
| `public-opensearch-domain.json`                   | OpenSearch domain policy with public principal is blocked.                                    |
| `public-s3-bucket-policy.json`                    | S3 bucket policy granting public object access is blocked.                                    |
| `public-admin-api-route.json`                     | Unauthenticated public API Gateway admin route is blocked.                                    |
| `public-rds-prod.json` + baseline                 | Existing unchanged risk is suppressed by a baseline.                                          |
| `public-rds-prod.json` + baseline + drift context | Worsened baseline risk remains blocking.                                                      |
| `public-rds-staging.json` + waiver                | Staging waiver suppresses the accepted exception.                                             |
| `public-rds-prod.json` + staging waiver           | Production use of the staging waiver is rejected.                                             |
| `public-rds-prod.json` + expected-public context  | Cloud context downgrades an expected public edge.                                             |
| `public-rds-prod.json` + drift context            | Cloud context upgrades actual public drift.                                                   |
