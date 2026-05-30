# Multi-Plan Guide

ChangeGate supports repeated `--plan` flags for coordinated changes:

```bash
changegate scan \
  --plan network/tfplan.json \
  --plan app/tfplan.json \
  --plan data/tfplan.json
```

Use this when a single team or review group owns the combined deployment decision.

## Separate Ownership

Run separate scans when plans have different owners, policies, waivers, or baselines:

```bash
changegate scan --plan network/tfplan.json --policy network/.changegate.yaml
changegate scan --plan app/tfplan.json --policy app/.changegate.yaml
```

## Limitations

External scanner imports currently require exactly one plan. If you import SARIF, Checkov, Trivy, KICS, Grype, or generic JSON findings, run ChangeGate once per plan.

## Reporting

For a combined human report:

```bash
changegate scan \
  --plan network/tfplan.json \
  --plan app/tfplan.json \
  --format markdown \
  --out changegate-summary.md
```
