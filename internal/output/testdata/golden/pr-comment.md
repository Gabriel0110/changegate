## ChangeGate: BLOCK

**1 findings**: 1 blocking, 0 warnings, 0 suppressed.

**Decision reasons**
- `MEETS_BLOCK_THRESHOLD` `aws_security_group.admin`: high severity and high confidence meets block threshold

**Top findings**
- `AWS_SG_WORLD_OPEN_ADMIN_PORT` `high/high` Security group opens SSH to the world on `aws_security_group.admin`
  Fix: Restrict administrative ingress to trusted CIDR ranges.
