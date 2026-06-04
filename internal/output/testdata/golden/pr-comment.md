## ChangeGate: BLOCK

**1 risk clusters** from 1 findings: 1 blocking, 0 warnings, 0 suppressed.

**Decision reasons**
- `MEETS_BLOCK_THRESHOLD` `Security group opens SSH to the world`: high severity and high confidence meets block threshold

**Risk clusters**
- `high/high` Security group opens SSH to the world (1 resources, 1 findings)
  Fix: Restrict administrative ingress to trusted CIDR ranges.
  Rules: `AWS_SG_WORLD_OPEN_ADMIN_PORT`
