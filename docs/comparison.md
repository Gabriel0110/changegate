# ChangeGate Compared With Generic IaC Scanners

Generic IaC scanners are useful. ChangeGate is not trying to replace every broad static scanner. It is a deployment gate: it evaluates the Terraform/OpenTofu plan that is about to apply, builds graph context, and returns one deploy decision.

## Positioning

| Tool type                     | Strength                                                                 | ChangeGate difference                                                                                                      |
| ----------------------------- | ------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------- |
| Checkov-style IaC scanning    | Broad static policy coverage across IaC files and frameworks             | ChangeGate focuses on the concrete plan, graph context, risk movement, and deployment decision.                            |
| Trivy-style security scanning | Broad vulnerability, container, SBOM, secret, and IaC coverage           | ChangeGate focuses on infrastructure change risk before apply and can import external findings as evidence.                |
| KICS-style query scanning     | Large query library for common IaC misconfiguration patterns             | ChangeGate focuses on high-confidence blocking, waiver/baseline governance, and review-ready blast-radius evidence.        |
| CSPM/CNAPP platforms          | Runtime cloud inventory, posture, exposure, identity, and threat context | ChangeGate is local and CI-first. Optional cloud context can enrich plan review, but ChangeGate is not a runtime platform. |

## Capability Comparison

| Capability                            | Broad IaC scanner     | ChangeGate                                 |
| ------------------------------------- | --------------------- | ------------------------------------------ |
| Static Terraform source checks        | Yes                   | Not the primary path                       |
| Terraform/OpenTofu plan-aware actions | Sometimes             | Yes                                        |
| Graph-aware resource relationships    | Sometimes limited     | Yes                                        |
| Public-to-sensitive path evidence     | Usually limited       | Built in for supported AWS paths           |
| IAM escalation path evidence          | Usually rule-oriented | Built in for supported deterministic paths |
| One CI deploy decision                | Usually no            | Yes                                        |
| Baselines and new-risk-only adoption  | Tool-specific         | Built in                                   |
| Expiring waiver governance            | Tool-specific         | Built in                                   |
| Audit evidence bundle                 | Usually separate      | Built in                                   |
| Offline default                       | Varies                | Yes                                        |
| External scanner findings             | Native output         | Import and correlate                       |

## When To Use Both

Use broad scanners for static breadth, compliance checklists, and ecosystem coverage. Use ChangeGate to decide whether the planned deployment should proceed.

ChangeGate can import SARIF, Checkov, Trivy, KICS, Grype, and generic JSON findings as external evidence:

```bash
changegate scan --plan tfplan.json --import-sarif checkov.sarif --import-trivy trivy.json
```

Imported findings are correlated with native graph-aware findings when possible.

## What This Means In Practice

A broad scanner may report:

```text
Security group allows ingress from 0.0.0.0/0.
```

ChangeGate tries to answer:

```text
Does this planned public entrypoint reach an admin workload or sensitive data asset?
Should CI allow, warn, or block this apply?
What evidence and remediation should reviewers see?
```

The recommended pattern is not either/or. Keep broad scanners where they already work. Feed their artifacts into ChangeGate when you want one governed deployment decision with baselines, waivers, graph context, and audit evidence.
