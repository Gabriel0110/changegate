# Output Formats

ChangeGate scan output is built around one stable report schema, `changegate.scan.report.v1`, and rendered into formats used by local terminals and CI systems.

## Supported formats

```bash
changegate scan --plan tfplan.json
changegate scan --plan tfplan.json --format json --out changegate.json
changegate scan --plan tfplan.json --format sarif --out changegate.sarif
changegate scan --plan tfplan.json --format junit --out changegate.junit.xml
changegate scan --plan tfplan.json --format markdown --out changegate.md
changegate scan --plan tfplan.json --format github-step-summary --out "$GITHUB_STEP_SUMMARY"
changegate scan --plan tfplan.json --format github-annotations
changegate scan --plan tfplan.json --format gitlab-code-quality --out gl-code-quality-report.json
changegate scan --plan tfplan.json --format pr-comment --out changegate-pr-comment.md
changegate scan --plan tfplan.json --format audit-bundle --out changegate-audit.zip
changegate scan --plan tfplan.json --audit-bundle changegate-audit.zip --format json --out changegate.json
```

## Canonical JSON

`--format json` emits the canonical report documented by [../schemas/changegate-report.schema.json](../schemas/changegate-report.schema.json). It includes:

* `schema_version`
* final `decision`
* plan and graph summaries
* optional external import summary with imported, deduplicated, correlated, downgraded, and upgraded counts
* risk summary, including suppressed and downgraded counts
* decision reason codes and human-readable reasons
* findings with evidence, remediation, fingerprints, and suppression context
* rule metadata used by integrations
* optional run metadata with CLI version, policy pack versions, plan/config digests, redaction status, and compliance mapping metadata

All finding evidence is normalized through the model redaction path before rendering. Sensitive evidence values are emitted as `(sensitive)`.

## SARIF

`--format sarif` emits SARIF 2.1.0 for GitHub code scanning and compatible viewers. Results include stable rule IDs, rule help and remediation, severity mapping, plan-file locations when available, and stable partial fingerprints:

* `changegateFingerprint/v1`
* `changegateDedupKey/v1`

## JUnit

`--format junit` renders findings as test cases. Blocking findings are failures, suppressed findings are skipped, and non-blocking findings are passing test cases with the finding encoded in the test name.

## Markdown

`--format markdown` and `--format pr-comment` render PR-comment-friendly Markdown with a decision summary, decision reasons, findings, evidence, and remediation.

`--format github-step-summary` renders a compact Markdown table suitable for GitHub Actions `GITHUB_STEP_SUMMARY`.

`--format github-annotations` renders GitHub workflow command annotations. Buildkite also recognizes this annotation style in many setups.

## GitLab Code Quality

`--format gitlab-code-quality` renders a GitLab Code Quality compatible JSON issue array with description, check name, fingerprint, severity, and plan-file location.

## Audit Bundle

`--format audit-bundle` renders a zip to the selected output target. `--audit-bundle changegate-audit.zip` writes the same archive as an additional artifact while still allowing another `--format` such as JSON, SARIF, or table output.

The archive is deterministic for the same scan inputs and contains:

* `changegate-audit/decision.json`
* `changegate-audit/findings.json`
* `changegate-audit/suppressed.json`
* `changegate-audit/waivers.json`
* `changegate-audit/baseline.json`
* `changegate-audit/policy.yaml`
* `changegate-audit/policy-digest.txt`
* `changegate-audit/plan-digest.txt`
* `changegate-audit/rule-pack-versions.json`
* `changegate-audit/environment.json`
* `changegate-audit/evidence.json`
* `changegate-audit/compliance.json`
* `changegate-audit/run-metadata.json`
* `changegate-audit/redaction-report.json`
* `changegate-audit/summary.md`

The bundle never stores the Terraform/OpenTofu plan body. It stores only the plan digest plus the already-redacted findings and evidence. Compliance mappings are metadata attached to real findings; they do not create additional risks or change the allow/warn/block decision.
