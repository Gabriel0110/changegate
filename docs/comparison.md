# ChangeGate Compared With Generic IaC Scanners

Generic IaC scanners are useful, but they usually inspect static configuration. ChangeGate is a deployment gate: it evaluates the plan that is about to apply.

| Capability | Generic IaC Scanner | ChangeGate |
| --- | --- | --- |
| Static Terraform file checks | Yes | No, not the primary path |
| Plan-aware actions | Often limited | Yes |
| Graph-aware resource relationships | Often limited | Yes |
| One deployment decision | Usually no | Yes |
| Baseline and waiver governance | Tool-specific | Built in |
| Audit evidence bundle | Usually separate | Built in |
| Offline default | Varies | Yes |
| External scanner findings | Native to the scanner | Import and correlate |

## When To Use Both

Use generic scanners for broad static coverage and compliance checklists. Use ChangeGate to decide whether the planned deployment should proceed.

ChangeGate can import SARIF, Checkov, Trivy, KICS, Grype, and generic JSON findings as external evidence:

```bash
changegate scan --plan tfplan.json --import-sarif checkov.sarif --import-trivy trivy.json
```

Imported findings are correlated with native graph-aware findings when possible.
