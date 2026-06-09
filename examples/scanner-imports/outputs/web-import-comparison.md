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
| Retained imported findings     |     2 |
| Deduplicated imported findings |     0 |
| Correlated imported findings   |     1 |
| Downgraded imported findings   |     1 |
| Upgraded imported findings     |     1 |
| Graph nodes                    |     5 |
| Graph edges                    |     5 |

## External scanner intelligence

ChangeGate imported 2 external findings, retained 2 after deduplication, and correlated 1 to the change graph.

| Source  | Findings |
| ------- | -------: |
| `grype` |        1 |
| `sarif` |        1 |

Key handling notes:

- `sarif` `correlated` `aws_lb.web`: scanner finding matched a changed graph resource through graph.alias
- `grype` `downgraded` `openssl`: imported finding did not correlate to a changed graph resource
- `sarif` `upgraded` `aws_lb.web`: graph context increases materiality of imported finding

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
- Fingerprint: `b37b4497a7c83d334f7aee95233adb4ad1adc7eea100647233e18facf9b26a7d`

Evidence:

- `external_scanner` `sarif`: finding imported from sarif
- `external_location` `main.tf:12`: SARIF result location
- `external_correlation` `graph.alias`: imported finding correlated to changed graph resource
- `external_decision` `upgraded`: external finding upgraded because graph evidence increases materiality

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
- Fingerprint: `a7e54214cc2e870fa1c1de83e1d85efddb8e6d7eb891dbe233d6c069286223c2`

Synthetic package vulnerability used to demonstrate external scanner import.

Evidence:

- `external_scanner` `grype`: finding imported from grype
- `external_vulnerability` `/image`: Grype vulnerability match
- `external_decision` `downgraded`: external finding downgraded because graph evidence was incomplete

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
