# External Scanner Import Examples

ChangeGate can ingest existing scanner artifacts and combine them with native plan-aware graph findings. These examples use sanitized outputs shaped like SARIF, Checkov, Trivy, KICS, and Grype results.

ChangeGate does not install or run those scanners. It reads their JSON or SARIF output, normalizes findings, deduplicates repeated evidence, correlates findings to changed graph resources when possible, and keeps native ChangeGate findings authoritative when richer graph evidence exists.

## Run The Examples

```bash
changegate scan \
  --plan examples/risk-tests/fixtures/public-s3-bucket-policy.json \
  --import-checkov examples/scanner-imports/artifacts/checkov.json \
  --import-trivy examples/scanner-imports/artifacts/trivy.json \
  --import-kics examples/scanner-imports/artifacts/kics.json \
  --format markdown \
  --out examples/scanner-imports/outputs/s3-import-comparison.md

changegate scan \
  --plan examples/risk-tests/fixtures/public-web-alb.json \
  --import-sarif examples/scanner-imports/artifacts/sample.sarif \
  --import-grype examples/scanner-imports/artifacts/grype.json \
  --format markdown \
  --out examples/scanner-imports/outputs/web-import-comparison.md
```

Both commands intentionally return exit code `1` in this demo. The S3 example is blocked by native ChangeGate evidence. The web example is blocked because the imported SARIF finding correlates to a changed public graph node and therefore becomes material to the deployment decision.

## What To Look For

- Imported rule IDs are prefixed with `EXT_<SOURCE>_`.
- Imported findings use policy packs such as `external:checkov` or `external:trivy`.
- When an imported finding maps to a changed graph resource, ChangeGate adds correlation evidence.
- If a native ChangeGate finding covers the same resource/category with stronger graph evidence, the native finding remains authoritative.
- Uncorrelated imported findings are still reported, but they do not become more important than high-confidence native plan evidence.

## Artifacts

| Artifact                                                     | Purpose                                                          |
| ------------------------------------------------------------ | ---------------------------------------------------------------- |
| [sample.sarif](artifacts/sample.sarif)                       | Minimal SARIF finding mapped to `aws_lb.web`.                    |
| [checkov.json](artifacts/checkov.json)                       | Checkov-style S3 public policy finding.                          |
| [trivy.json](artifacts/trivy.json)                           | Trivy misconfiguration finding for the same S3 policy.           |
| [kics.json](artifacts/kics.json)                             | KICS finding for the same S3 policy.                             |
| [grype.json](artifacts/grype.json)                           | Package vulnerability import example.                            |
| [s3-import-comparison.md](outputs/s3-import-comparison.md)   | Native S3 finding plus imported scanner evidence.                |
| [web-import-comparison.md](outputs/web-import-comparison.md) | Expected public web plan with SARIF and Grype imported findings. |

See [external scanner adapters](../../docs/adapters.md) for supported flags and normalization details.
