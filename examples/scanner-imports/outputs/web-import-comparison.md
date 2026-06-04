# ChangeGate: BLOCK

| Metric                         | Value |
| ------------------------------ | ----: |
| Risk clusters                  |     2 |
| Findings                       |     2 |
| Blocking                       |     1 |
| Warnings                       |     1 |
| Suppressed                     |     0 |
| Downgraded                     |     1 |
| Imported findings              |     2 |
| Deduplicated imported findings |     0 |
| Correlated imported findings   |     1 |
| Graph nodes                    |     5 |
| Graph edges                    |     5 |

## Decision reasons

- `MEETS_BLOCK_THRESHOLD` `Public web load balancer should have compensating controls.`: graph context increases materiality of imported finding

## Risk clusters

### Public web load balancer should have compensating controls.

- Decision: `block`
- Severity: `high`, confidence: `high`
- Affected resources: 1
- Supporting findings: 1
- Rules: `EXT_SARIF_CG_PUBLIC_WEB_EDGE_REVIEW`
- Primary fix: Constrain public exposure to the smallest reviewed entry point.
- Resources: `aws_lb.web`

### CVE-2026-0001 in openssl

- Decision: `warn`
- Severity: `medium`, confidence: `medium`
- Affected resources: 1
- Supporting findings: 1
- Rules: `EXT_GRYPE_CVE_2026_0001`
- Primary fix: Review the control-specific requirement and update the Terraform/OpenTofu resource or policy exception.
- Resources: `openssl`

## Finding details

### Public web load balancer should have compensating controls.

- Rule: `EXT_SARIF_CG_PUBLIC_WEB_EDGE_REVIEW`
- Resource: `aws_lb.web`
- Severity: `high`, confidence: `high`
- Fingerprint: `e971f4b8926a31cfe01a923facce855dac7bd4b9abd797e1020c5341b5216dc3`

Evidence:

- `external_scanner` `sarif`: finding imported from sarif
- `external_location` `main.tf:12`: SARIF result location
- `external_correlation` `graph.node`: imported finding correlated to changed graph resource

Remediation:

- Constrain public exposure to the smallest reviewed entry point.
- Document any intentional public exposure in policy or a time-bounded waiver.
- Prefer private subnets, internal load balancers, or authenticated edge controls.
- Remove public CIDRs unless internet access is required.
- Why this works: Reducing public reachability lowers exploitability and leaves fewer assets directly reachable from the internet.
- Fix confidence: `medium`
- Automatic patch: `false`
- Patch suggestion: Public exposure requires review (ChangeGate does not auto-apply exposure changes because safe CIDRs, proxy placement, and business intent are environment-specific.)
- Owner hints: `service=web`
- Next step: Attach evidence of the selected mitigation before apply.
- Next step: Treat as release-blocking unless a reviewer approves a time-bounded waiver.

### CVE-2026-0001 in openssl

- Rule: `EXT_GRYPE_CVE_2026_0001`
- Resource: `openssl`
- Severity: `medium`, confidence: `medium`
- Fingerprint: `0eef8e3bfec15c4089843bd43941de17c0d80b23f9b927c1d038b8f9d41446cf`

Synthetic package vulnerability used to demonstrate external scanner import.

Evidence:

- `external_scanner` `grype`: finding imported from grype
- `external_vulnerability` `/image`: Grype vulnerability match

Remediation:

- Review the control-specific requirement and update the Terraform/OpenTofu resource or policy exception.
- Attach evidence to the pull request.
- Confirm whether the control applies to this environment.
- Update the resource configuration or add a time-bounded waiver with owner approval.
- Why this works: Control-specific review keeps policy exceptions intentional and auditable.
- Fix confidence: `medium`
- Automatic patch: `false`
- Patch suggestion: Compliance fix depends on the control (ChangeGate does not auto-patch generic compliance findings without a specific resource-safe template.)
- Next step: Fix before merge when practical, or track with an owner and due date.
