# External Scanner Adapters

ChangeGate is not a scanner wrapper. Native plan analysis works without external tools, and adapter inputs are optional evidence that is normalized into the same finding, waiver, baseline, policy, and output model.

## Supported imports

```bash
changegate scan --plan tfplan.json --import-sarif checkov.sarif
changegate scan --plan tfplan.json --import-json findings.json
changegate scan --plan tfplan.json --import-checkov checkov.json
changegate scan --plan tfplan.json --import-trivy trivy.json
changegate scan --plan tfplan.json --import-kics kics.json
changegate scan --plan tfplan.json --import-grype grype.json
```

All import flags are repeatable and can be combined:

```bash
changegate scan \
  --plan tfplan.json \
  --import-sarif checkov.sarif \
  --import-trivy trivy.json \
  --import-kics kics.json
```

No external scanner is installed or executed by ChangeGate. The flags only read existing JSON or SARIF files.

## Generic JSON format

`--import-json` accepts either a top-level array or an object with `findings` or `results`.

```json
{
  "findings": [
    {
      "rule_id": "CUSTOM_PUBLIC_BUCKET",
      "title": "S3 bucket is public",
      "description": "Scanner found public bucket access.",
      "resource_address": "aws_s3_bucket.logs",
      "category": "public",
      "severity": "high",
      "confidence": "medium",
      "remediation": "Enable public access block."
    }
  ]
}
```

Recognized fields are `rule_id`, `id`, `title`, `name`, `description`, `resource_address`, `resource`, `provider`, `category`, `severity`, `confidence`, `remediation`, and `evidence`.

## Normalization

Imported findings are labeled with external metadata:

- `rule_id` is prefixed with `EXT_<SOURCE>_`.
- `policy_pack` is set to `external:<source>`.
- `policy_pack_version` is set to `import`.
- evidence includes `type: external_scanner`.

This makes imported findings visually distinct while keeping them suppressable with the same waiver, baseline, and policy mechanisms as native findings.

## Scanner intelligence

Imported findings are deduplicated by stable fingerprint when the same scanner artifact is imported more than once. Imported findings are also deduplicated against native findings by fingerprint and by resource/category. Native ChangeGate findings win because they have richer graph evidence.

If an imported finding references a changed graph resource, ChangeGate adds `external_correlation` evidence. Correlation uses explicit Terraform/OpenTofu resource addresses and graph aliases such as ARN, provider ID, bucket name, function name, role ARN, resource name, and tags. If the graph shows public exposure or sensitive-data access for that resource, ChangeGate can upgrade the imported finding's materiality. If the imported finding cannot be correlated to a changed resource, ChangeGate downgrades high-severity/high-confidence imported noise.

JSON and Markdown reports include an external scanner intelligence summary with:

- imported and retained finding counts
- repeated scanner duplicates
- imported findings superseded by native ChangeGate findings
- graph-correlated imported findings
- imported findings upgraded or downgraded by graph context
- short explanations for the most important scanner-handling decisions

SARIF location-only results are retained, but ChangeGate only correlates them to the graph when the result includes a resource identifier, resource property, ARN, provider ID, or other graph alias. Terraform plan JSON does not contain source-code line ranges, so ChangeGate does not infer resource identity from a file path alone.

Adapter normalization is tested against real scanner JSON fixtures for Checkov, Trivy, KICS, and Grype in addition to minimal schema fixtures. This keeps parser behavior tied to actual tool output shapes while preserving ChangeGate's local-only model: external tools are never installed or run by ChangeGate.

For copy-pasteable sample artifacts and generated output snapshots, see [external scanner import examples](../examples/scanner-imports).

## Failure behavior

Adapter parse and file errors are warnings by default. Native scanning continues:

```bash
changegate scan --plan tfplan.json --import-sarif missing.sarif
```

Use `--fail-on-import-error` when CI should fail if an external scanner artifact is missing or malformed:

```bash
changegate scan \
  --plan tfplan.json \
  --import-sarif checkov.sarif \
  --fail-on-import-error
```

## Current limits

External imports are supported for single-plan scans. For monorepos with multiple plans, run one ChangeGate scan per plan when importing external scanner output so graph correlation stays unambiguous.
