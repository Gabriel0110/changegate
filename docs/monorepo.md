# Monorepos and Multi-Plan Scans

Large infrastructure repositories usually have multiple Terraform/OpenTofu roots. Choose the scan shape based on ownership.

## One Owner Per Root

Run one ChangeGate job per root when teams own policies independently:

```bash
changegate scan --plan services/api/tfplan.json --policy services/api/.changegate.yaml
changegate scan --plan platforms/network/tfplan.json --policy platforms/network/.changegate.yaml
```

This gives each team separate evidence, thresholds, waivers, and baselines.

## One Coordinated Change

Use repeated `--plan` values when one reviewer group owns the full change:

```bash
changegate scan \
  --plan services/api/tfplan.json \
  --plan platforms/network/tfplan.json \
  --format markdown \
  --out changegate-summary.md
```

External scanner imports require exactly one plan, so run one scan per plan when using `--import-sarif`, `--import-checkov`, `--import-trivy`, `--import-kics`, or `--import-grype`.

## Changed Roots Only

In pull requests, use your CI path filters to plan only changed roots. Then use `--changed-only` if you want policy enforcement scoped to resources changed in each plan:

```bash
changegate scan --plan tfplan.json --changed-only
```
