# ChangeGate: BLOCK

| Metric | Value |
| --- | ---: |
| Risk clusters | 1 |
| Findings | 1 |
| Blocking | 1 |
| Warnings | 0 |
| Suppressed | 0 |
| Downgraded | 0 |
| Graph nodes | 12 |
| Graph edges | 7 |

## Decision reasons

- `MEETS_BLOCK_THRESHOLD` `Security group opens SSH to the world`: high severity and high confidence meets block threshold

## Risk clusters

### Security group opens SSH to the world

- Decision: `block`
- Severity: `high`, confidence: `high`
- Affected resources: 1
- Supporting findings: 1
- Rules: `AWS_SG_WORLD_OPEN_ADMIN_PORT`
- Primary fix: Restrict administrative ingress to trusted CIDR ranges.
- Resources: `aws_security_group.admin`

## Finding details

### Security group opens SSH to the world

- Rule: `AWS_SG_WORLD_OPEN_ADMIN_PORT`
- Resource: `aws_security_group.admin`
- Severity: `high`, confidence: `high`
- Fingerprint: `57487a2798ec56aabc46e5797f4c228a8d23209e9df713b20f0dea470a571ced`

The planned security group permits public administrative ingress.

Evidence:
- `attribute` `ingress[0].cidr_blocks`: Ingress allows SSH from the public internet.
- `attribute` `tags.secret`: Sensitive tag value was redacted.

Remediation:
- Restrict administrative ingress to trusted CIDR ranges.
- Replace 0.0.0.0/0 with a trusted bastion, VPN, or private subnet range.
- Prefer SSM Session Manager for administrative access.

