# Audit-Mode Rollout

Start by collecting evidence without blocking deploys.

## Phase 1: Observe

```bash
changegate scan --plan tfplan.json --mode audit --audit-bundle changegate-audit.zip
```

Archive the bundle from every CI run. Review the most common findings, owners, and resources.

## Phase 2: Baseline Existing Risk

```bash
changegate baseline create --plan tfplan.json --out .changegate/baseline.json
```

Use the baseline to avoid blocking old findings while you focus on new risk.

## Phase 3: Warn

```bash
changegate scan --plan tfplan.json --mode warn --baseline .changegate/baseline.json --new-only
```

Warnings make risk visible without stopping deployment.

## Phase 4: Block New High-Confidence Risk

```bash
changegate scan --plan tfplan.json --mode block --baseline .changegate/baseline.json --new-only
```

Keep waivers time-bound and owner-approved for legitimate exceptions.
