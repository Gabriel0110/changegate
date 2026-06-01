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
* `impact.json` and `impact.md` contain the Security Impact Statement generated from the same scan report.
* `review-comment.md` contains the sticky PR/MR review comment body that can be posted by the review integrations.
* `graph.json` contains a sanitized graph evidence export with node identities, kinds, actions, and edge provenance, but not raw resource values.
* `attack-paths.json` contains the attack path summaries promoted into review output.
* `cloud-context-summary.json` records only cloud-context metadata, capability coverage, resource counts, relationship counts, and diagnostics. It does not include full cloud inventory.
* `risk-tests.json` records whether this bundle came from a risk-test run.
* `hcp-run-task.json` records run-task-compatible pass/fail evidence for future adapters and later HCP Terraform integrations.

The bundle does not include raw plan JSON or raw cloud inventory. It includes only the plan digest, redacted finding evidence, sanitized graph evidence, and summary-level cloud-context metadata.

## Compliance mapping

Compliance metadata is intentionally separate from rule evaluation. A rule maps to frameworks such as CIS AWS, NIST 800-53, PCI DSS, SOC 2, or ISO 27001, but ChangeGate only reports framework coverage when an actual finding exists.

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
    soc2:
      - "CC6.6"
      - "CC7.1"
    iso_27001:
      - "A.8.20"
      - "A.8.22"
```

This means compliance reports can help audit teams route evidence without turning checklist metadata into separate blocking risks.

The bundled AWS rule pack has mapping coverage tests so newly added stable AWS rules cannot silently ship without compliance metadata. These mappings are evidence routing aids, not legal claims of compliance.

Teams can add organization-specific mappings in `.changegate.yaml`:

```yaml
compliance:
  mappings:
    ORG_QUEUE_REVIEW:
      frameworks:
        soc2:
          - CC8.1
        iso_27001:
          - A.5.8
```

Custom mappings can reference built-in or custom rule IDs. They appear in `compliance.json` only when a matching finding exists.
