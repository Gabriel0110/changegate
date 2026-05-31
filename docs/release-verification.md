# Release Verification

Use these steps before installing ChangeGate in CI.

## Pre-release confidence suite

Maintainers should run this suite before publishing a release candidate. The local
checks are required for every release. The live checks should be run before major
feature releases that change Review Intelligence, cloud context, graph behavior,
plan parsing, provider integrations, or packaging.

### Local regression checks

```bash
go test ./...
go test -race ./...
golangci-lint run
govulncheck ./...
```

### Feature and output checks

Use the sanitized risk-test corpus to verify deterministic decisions,
baselines, waivers, graph evidence, cloud-context enrichment, and attack paths:

```bash
changegate test examples/risk-tests

changegate scan --plan examples/risk-tests/fixtures/public-alb-ecs-rds.json \
  --format json --out /tmp/changegate.json
changegate scan --plan examples/risk-tests/fixtures/public-alb-ecs-rds.json \
  --format sarif --out /tmp/changegate.sarif
changegate scan --plan examples/risk-tests/fixtures/public-alb-ecs-rds.json \
  --format gitlab-code-quality --out /tmp/gl-code-quality-report.json

changegate impact --plan examples/risk-tests/fixtures/public-alb-ecs-rds.json \
  --format markdown --out /tmp/changegate-impact.md
changegate graph path --plan examples/risk-tests/fixtures/public-alb-ecs-rds.json \
  --from aws_lb.admin --to aws_db_instance.customer --format json
changegate graph exposure --plan examples/risk-tests/fixtures/public-alb-ecs-rds.json \
  --resource aws_ecs_service.admin --format json
changegate attack-paths --plan examples/risk-tests/fixtures/passrole-lambda-update.json \
  --format json
```

Blocking fixtures should exit with status `1`; that is the expected enforcement
result, not a test failure.

### Performance and release checks

```bash
go test ./internal/performance \
  -run 'Test(SmallPlanPerformanceBudget|LargePlanMemoryBudget|ReviewIntelligencePerformanceBudget|LargeGraphPathExtractionBudget|PRCommentRenderBudget)$' \
  -bench 'Benchmark(SmallScan|GraphPathSearch|ImpactBuild|PRCommentRender|AttackPathDetectors)$' \
  -benchtime=1x -count=1

CHANGEGATE_SKIP_SBOM=1 CHANGEGATE_SKIP_SIGN=1 \
  scripts/release-build.sh v0.0.0-release-test
```

For a packaging smoke test, rebuild the Docker image and run the risk-test corpus
inside the container:

```bash
docker build -t changegate:release-test .
docker run --rm changegate:release-test version
docker run --rm -v "$PWD/examples/risk-tests:/fixtures:ro" \
  changegate:release-test --no-color test /fixtures
```

### Live Review Intelligence checks

Run these against private provider sandboxes or draft pull requests only. Use
provider tokens from a secret manager or CI secret store; do not put literals in
shell history.

```bash
changegate review github --report /tmp/changegate.json \
  --comment --repo OWNER/REPO --pr PR_NUMBER
changegate review github --report /tmp/changegate.json \
  --comment --repo OWNER/REPO --pr PR_NUMBER
```

Verify that the GitHub pull request contains exactly one comment with the
`<!-- changegate-review -->` marker after both runs.

```bash
changegate review gitlab --report /tmp/changegate.json \
  --comment --project PROJECT_ID_OR_PATH --merge-request MR_IID
changegate review gitlab --report /tmp/changegate.json \
  --comment --project PROJECT_ID_OR_PATH --merge-request MR_IID
```

Verify that the GitLab merge request contains exactly one note with the
`<!-- changegate-review -->` marker after both runs.

### Live AWS context checks

Use a dedicated sandbox account and low-cost resources only. Avoid applying
RDS, ALB, NAT Gateway, EKS, OpenSearch, ElastiCache, or other cost-heavy
services for release verification. A useful live topology is:

- VPC, public subnet, internet gateway, route table, and route association.
- Security group with initially restricted admin ingress.
- Security group representing a sensitive data tier.
- S3 bucket with public access block enabled.
- IAM role and managed policy that read the bucket.

After applying that topology in the sandbox account, collect and inspect a
redacted offline snapshot:

```bash
changegate context aws snapshot \
  --out /tmp/aws-context.json \
  --collect identity,network,iam,data \
  --regions us-east-2 \
  --timeout 3m
```

Then generate a Terraform or OpenTofu plan that opens the admin ingress to
`0.0.0.0/0`, convert it with `terraform show -json` or `tofu show -json`, and
scan it with the live snapshot:

```bash
changegate scan --plan /tmp/tfplan.json \
  --context-file /tmp/aws-context.json \
  --format json --out /tmp/live-scan.json
changegate impact --plan /tmp/tfplan.json \
  --context-file /tmp/aws-context.json \
  --format markdown --out /tmp/live-impact.md
```

The risky plan should block. Destroy the sandbox topology immediately after the
test and verify no resources with the test tag remain.

## Verify archive checksums

```bash
curl -fsSLO https://github.com/Gabriel0110/changegate/releases/download/vX.Y.Z/checksums.txt
curl -fsSLO https://github.com/Gabriel0110/changegate/releases/download/vX.Y.Z/changegate_X.Y.Z_linux_amd64.tar.gz
shasum -a 256 -c checksums.txt --ignore-missing
```

`scripts/install.sh` performs this check automatically and refuses to install when the checksum does not match.

## Verify signed checksums

```bash
curl -fsSLO https://github.com/Gabriel0110/changegate/releases/download/vX.Y.Z/checksums.txt.sig
curl -fsSLO https://github.com/Gabriel0110/changegate/releases/download/vX.Y.Z/checksums.txt.pem
cosign verify-blob \
  --certificate checksums.txt.pem \
  --signature checksums.txt.sig \
  checksums.txt
```

## Verify GitHub artifact attestations

```bash
gh attestation verify changegate_X.Y.Z_linux_amd64.tar.gz \
  --repo Gabriel0110/changegate
```

## Verify Docker image signature

```bash
cosign verify ghcr.io/Gabriel0110/changegate:vX.Y.Z
```

## Install a pinned version

```bash
export CHANGEGATE_VERSION=vX.Y.Z
curl -fsSL "https://raw.githubusercontent.com/Gabriel0110/changegate/${CHANGEGATE_VERSION}/scripts/install.sh" | bash
```

To verify unpublished local release artifacts, serve the `dist` directory and
point the installer at that base URL:

```bash
CHANGEGATE_VERSION=vX.Y.Z \
CHANGEGATE_BASE_URL=http://127.0.0.1:8765 \
CHANGEGATE_INSTALL_DIR=/tmp/changegate-bin \
  scripts/install.sh
```

The GitHub Action wrapper also requires a pinned `version` input:

```yaml
- uses: Gabriel0110/changegate@vX.Y.Z
  with:
    version: vX.Y.Z
    plan: tfplan.json
```
