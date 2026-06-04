## ChangeGate: BLOCK

**1 risk cluster** from 1 finding: 1 blocking, 0 warnings, 0 suppressed.

### Decision Reasons

- `MEETS_BLOCK_THRESHOLD` `Security group opens SSH to the world`: high severity and high confidence meets block threshold

### Risk Clusters

#### 1. Security group opens SSH to the world

- Severity: `high`
- Confidence: `high`
- Decision: `block`
- Affected resources: 1
- Supporting findings: 1

**Fix:** Restrict administrative ingress to trusted CIDR ranges.

Rules:

- `AWS_SG_WORLD_OPEN_ADMIN_PORT`
