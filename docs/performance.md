# Performance and Scale

ChangeGate keeps the default scan path offline and bounded so it is practical in pull request CI.

## Scan controls

```bash
changegate scan --plan tfplan.json --timeout 2m
changegate scan --plan tfplan.json --max-findings 100
changegate scan --plan tfplan.json --changed-only
```

* `--timeout` bounds the overall scan. Use Go duration values such as `30s`, `2m`, or `5m`.
* `--max-findings` caps serialized findings while preserving the final decision and risk summary from the full evaluation.
* `--changed-only` enforces only findings on resources changed by the plan. Findings outside the changed set are still evaluated, but policy suppresses them for the deployment decision.

Machine-readable outputs are not polluted with progress text. Human progress output is intentionally reserved for future long-running workflows where it can be emitted safely.

## Scale Expectations

ChangeGate is designed for pull-request and merge-request pipelines where the scan must finish quickly and produce deterministic output. Large plans should use explicit bounds such as `--timeout`, `--max-findings`, and `--changed-only` so CI behavior remains predictable.

For monorepos, prefer scanning only changed Terraform/OpenTofu roots or passing the relevant plan files explicitly. See [monorepos and multi-plan scans](monorepo.md) and [multi-plan guide](multi-plan.md).
