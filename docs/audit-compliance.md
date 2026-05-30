# Audit Evidence and Compliance Metadata

ChangeGate can emit a security-team archive for every CI scan:

```bash
changegate scan --plan tfplan.json --audit-bundle changegate-audit.zip
```

Use `--audit-bundle` when the pipeline also needs another output format:

```bash
changegate scan --plan tfplan.json --format sarif --out changegate.sarif --audit-bundle changegate-audit.zip
```

## Bundle contents

The zip uses a stable `changegate-audit/` prefix and deterministic member ordering:

* `decision.json` records the allow/warn/block decision, reason codes, decision reasons, and risk summary.
* `findings.json` contains the already-redacted canonical findings.
* `suppressed.json` contains only findings with active suppressions.
* `waivers.json` contains waiver application evidence when a waiver file is configured.
* `baseline.json` contains baseline diff evidence when a baseline is configured.
* `policy.yaml` contains the active policy file, or the generated default policy stub.
* `policy-digest.txt` and `plan-digest.txt` contain SHA-256 digests.
* `rule-pack-versions.json` records bundled policy pack versions.
* `environment.json` records non-secret scan context, plan summary, graph summary, decision, and optional cloud-context timestamp.
* `evidence.json` contains finding evidence and decision reasons.
* `compliance.json` contains rule-to-framework mappings and mapped actual findings.
* `run-metadata.json` contains CLI version, build metadata, digests, policy pack versions, and redaction status.
* `redaction-report.json` summarizes sensitive evidence counts.
* `summary.md` is a human-readable archive summary.

The bundle does not include raw plan JSON. It includes only the plan digest and redacted report evidence.

## Compliance mapping

Compliance metadata is intentionally separate from rule evaluation. A rule maps to frameworks such as CIS AWS, NIST 800-53, or PCI DSS, but ChangeGate only reports framework coverage when an actual finding exists.

Example:

```yaml
AWS_PUBLIC_RDS_INSTANCE:
  frameworks:
    cis_aws:
      - "2.3.3"
    nist_800_53:
      - "AC-4"
      - "SC-7"
    pci_dss:
      - "1.2"
```

This means compliance reports can help audit teams route evidence without turning checklist metadata into separate blocking risks.
