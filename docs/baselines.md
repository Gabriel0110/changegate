# Baselines

Baselines let teams adopt ChangeGate without fixing every existing infrastructure risk on day one. A baseline records the current finding fingerprints, then `--new-only` enforcement suppresses matching existing risks while still enforcing new or changed findings.

## Create a baseline

```bash
changegate baseline create \
  --plan tfplan.json \
  --out .changegate/baseline.json \
  --expires-in-days 30
```

The baseline file is deterministic, reviewable JSON. It stores non-secret finding metadata only:

* fingerprint
* deduplication key
* rule ID
* resource address
* provider
* category
* severity
* confidence
* title

Evidence values are not stored in the baseline.

## Enforce only new findings

```bash
changegate scan \
  --plan tfplan.json \
  --baseline .changegate/baseline.json \
  --new-only
```

Findings whose fingerprints already exist in the baseline are marked with `EXISTING_RISK`, suppressed, and counted under `suppressed`. New or changed findings are evaluated normally and can still block.

## Compare current findings to a baseline

```bash
changegate baseline diff \
  --baseline .changegate/baseline.json \
  --plan tfplan.json \
  --max-age-days 30 \
  --require-expiration
```

Diff categories:

* `new`: present now, absent from the baseline
* `unchanged`: matching fingerprint in the baseline
* `changed`: similar rule/category/provider/severity/confidence but changed fingerprint, commonly caused by a resource rename or changed evidence path
* `stale`: present in the baseline, absent from current findings

Stale entries should be removed from the baseline as resources are fixed or deleted.

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

Security teams can require expiring baselines by setting `require_expiration: true` and can warn on old baselines with `max_age_days`.

## Multiple plans

Baseline commands support repeated `--plan` flags:

```bash
changegate baseline create \
  --plan services/api/tfplan.json \
  --plan platforms/network/tfplan.json \
  --out .changegate/baseline.json
```
