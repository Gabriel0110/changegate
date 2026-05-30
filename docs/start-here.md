# Start Here

ChangeGate is a deployment risk gate for Terraform and OpenTofu plans. It is meant to run after `terraform plan` and before `terraform apply`.

Use it when you want to answer one CI question:

> Is this planned infrastructure change safe enough to deploy automatically?

ChangeGate does not need cloud credentials by default. It reads `terraform show -json` or `tofu show -json`, builds a graph of changing resources, evaluates high-confidence rules, and returns `allow`, `warn`, or `block`.

## First Run

```bash
terraform plan -out=tfplan
terraform show -json tfplan > tfplan.json
changegate scan --plan tfplan.json
```

## Read The Result

* `ALLOW`: no blocking or warning findings met policy thresholds.
* `WARN`: risk exists, but current mode or thresholds do not block.
* `BLOCK`: at least one high-confidence risk met the blocking policy.

Every finding includes evidence, a stable fingerprint, remediation guidance, and decision reasons.

## Rollout Path

1. Run in audit mode and archive bundles:

```bash
changegate scan --plan tfplan.json --mode audit --audit-bundle changegate-audit.zip
```

2. Create a baseline for existing known risks:

```bash
changegate baseline create --plan tfplan.json --out .changegate/baseline.json
```

3. Enforce only new risk first:

```bash
changegate scan --plan tfplan.json --baseline .changegate/baseline.json --new-only
```

4. Move to default blocking when teams understand the signal.

## Next Docs

* [Five-minute quickstart](quickstart.md)
* [GitHub Actions](github-actions.md)
* [Audit rollout](audit-rollout.md)
* [Troubleshooting](troubleshooting.md)
