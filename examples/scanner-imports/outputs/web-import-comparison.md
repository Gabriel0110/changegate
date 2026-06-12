# ChangeGate: BLOCK

| Metric | Value |
| --- | ---: |
| Risk clusters | 2 |
| Findings | 2 |
| Blocking | 1 |
| Warnings | 1 |
| Suppressed | 0 |
| Downgraded | 1 |
| Imported findings | 2 |
| Retained imported findings | 2 |
| Deduplicated imported findings | 0 |
| Correlated imported findings | 1 |
| Downgraded imported findings | 1 |
| Upgraded imported findings | 1 |
| Graph nodes | 5 |
| Graph edges | 5 |

## External scanner intelligence

ChangeGate imported 2 external findings, retained 2 after deduplication, and correlated 1 to the change graph.

| Source | Findings |
| --- | ---: |
| `grype` | 1 |
| `sarif` | 1 |

Key handling notes:
- `sarif` correlated `aws_lb.web`: scanner finding matched a changed graph resource through resource alias
- `grype` downgraded `openssl`: imported finding did not correlate to a changed graph resource
- `sarif` upgraded `aws_lb.web`: graph context increases materiality of imported finding

## Decision reasons

- **Public web load balancer should have compensating controls:** graph context increases materiality of imported finding

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
- Primary fix: Upgrade or replace the affected package version, or document an accepted vulnerability exception with an owner and expiration.
- Resources: `openssl`

## Finding details

### Public web load balancer should have compensating controls.

- Rule: `EXT_SARIF_CG_PUBLIC_WEB_EDGE_REVIEW`
- Resource: `aws_lb.web`
- Severity: `high`, confidence: `high`
- Fingerprint: `b37b4497a7c83d334f7aee95233adb4ad1adc7eea100647233e18facf9b26a7d`

Evidence:
- **aws_lb.web:** finding imported from sarif
- **aws_lb.web:** SARIF result location
- **aws_lb.web:** imported finding correlated to changed graph resource
- **aws_lb.web:** external finding upgraded because graph evidence increases materiality

Remediation:

**Primary fix:** Constrain public exposure to the smallest reviewed entry point.

Recommended actions:
- Document any intentional public exposure in policy or a time-bounded waiver.
- Prefer private subnets, internal load balancers, or authenticated edge controls.
- Remove public CIDRs unless internet access is required.

Fix options:
- **Make the endpoint private** (preferred): Move the exposed resource behind private networking or an internal load balancer.
- **Restrict ingress**: Keep the endpoint public only for reviewed CIDRs or authenticated edge controls.

Review notes:
- Owner hint: `service=web`
- Effort: medium
- Downtime risk: medium
- Attach evidence of the selected mitigation before apply.
- Treat as release-blocking unless a reviewer approves a time-bounded waiver.

### CVE-2026-0001 in openssl

- Rule: `EXT_GRYPE_CVE_2026_0001`
- Resource: `openssl`
- Severity: `medium`, confidence: `medium`
- Fingerprint: `a7e54214cc2e870fa1c1de83e1d85efddb8e6d7eb891dbe233d6c069286223c2`

Synthetic package vulnerability used to demonstrate external scanner import.

Evidence:
- **openssl:** finding imported from grype
- **openssl:** Grype vulnerability match
- **openssl:** external finding downgraded because graph evidence was incomplete

Remediation:

**Primary fix:** Upgrade or replace the affected package version, or document an accepted vulnerability exception with an owner and expiration.

Recommended actions:
- Rebuild and rescan the artifact that produced the imported vulnerability finding.
- Upgrade the affected package to a fixed version when one is available.
- Use a time-bounded waiver only when the vulnerability is not exploitable in the deployed context.

Fix options:
- **Upgrade package** (preferred): Move the affected dependency or OS package to a fixed version and regenerate the scanner output.
- **Accept with expiration**: Use a waiver only when compensating controls or non-exploitability are documented.

Review notes:
- Effort: medium
- Downtime risk: low
- Fix before merge when practical, or track with an owner and due date.
