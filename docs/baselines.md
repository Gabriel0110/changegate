# Baselines

Baselines let you adopt ChangeGate without fixing every existing infrastructure risk on day one. A baseline records the current finding fingerprints, then `--new-only` enforcement suppresses matching existing risks while still enforcing new or changed findings.

## Create a baseline

```bash
changegate baseline create \
  --plan tfplan.json \
  --out .changegate/baseline.json \
  --expires-in-days 30
```

The baseline file is deterministic, reviewable JSON. It stores non-secret finding metadata only:

- fingerprint
- deduplication key
- rule ID
- resource address
- provider
- category
- severity
- confidence
- title

Evidence values are not stored in the baseline.

## Enforce only new findings

```bash
changegate scan \
  --plan tfplan.json \
  --baseline .changegate/baseline.json \
  --new-only
```

Findings whose fingerprints already exist in the baseline are marked with `EXISTING_RISK`, suppressed, and counted under `suppressed`. New or changed findings are evaluated normally and can still block.

ChangeGate also tracks baseline risk movement. `--new-only` suppresses existing unchanged risk, but it must not suppress a finding whose stable fingerprint lineage has worsened. A finding is treated as worsened when severity increases, confidence reaches high, decision impact increases, graph evidence newly reaches sensitive data, cloud context adds stronger evidence, or a prior waiver no longer applies.

## Compare current findings to a baseline

```bash
changegate baseline diff \
  --baseline .changegate/baseline.json \
  --plan tfplan.json \
  --max-age-days 30 \
  --require-expiration
```

Diff categories:

- `new`: present now, absent from the baseline
- `unchanged`: matching fingerprint in the baseline
- `changed`: similar rule/category/provider/severity/confidence but changed fingerprint, commonly caused by a resource rename or changed evidence path
- `stale`: present in the baseline, absent from current findings
- `new_risk`: absent from the baseline and enforceable as new risk
- `existing_unchanged`: existing risk with no material movement
- `existing_worsened`: existing risk whose impact increased and should remain visible/enforceable
- `existing_improved`: existing risk whose impact decreased
- `resolved`: baseline risk absent from current findings

Stale or resolved entries should be removed from the baseline as resources are fixed or deleted.

## Policy integration

Policy files can reference a baseline:

```yaml
version: 1
mode: block
baseline:
  file: .changegate/baseline.json
  mode: new-risk-only
  max_age_days: 30
  require_expiration: true
```

Require expiring baselines by setting `require_expiration: true`, and warn on old baselines with `max_age_days`.

## Multiple plans

Baseline commands support repeated `--plan` flags:

```bash
changegate baseline create \
  --plan services/api/tfplan.json \
  --plan platforms/network/tfplan.json \
  --out .changegate/baseline.json
```
