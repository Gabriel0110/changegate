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

## Benchmarks

Run the benchmark suite:

```bash
go test ./internal/performance -run '^$' -bench . -benchmem
```

Capture CPU and memory profiles:

```bash
scripts/perf-profile.sh profiles
go tool pprof profiles/cpu.pprof
go tool pprof profiles/mem.pprof
```

The benchmark suite covers:

* full small and large scans
* graph construction
* bounded graph path extraction
* Security Impact Statement generation
* PR comment rendering
* attack path detection
* output rendering
* cloud-context enrichment
* cloud-context cache loading

CI runs performance budget tests for small scans, large-plan allocation, scan-plus-impact latency, 10,000-node path extraction with cloud context, and PR comment rendering. It also runs one-iteration benchmarks for small scans, graph paths, impact generation, PR comment rendering, and attack path detection to catch large regressions without making normal checks noisy.
