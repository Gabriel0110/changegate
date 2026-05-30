# Waivers

Waivers are reviewed, expiring exceptions for findings that should not block temporarily. They are intended for security-team workflows where every exception needs an owner, reason, scope, and expiration.

## Waiver file

```yaml
version: 1
waivers:
  - id: WVR-001
    rule_id: AWS_PUBLIC_RDS_INSTANCE
    resource: aws_db_instance.analytics_replica
    fingerprint: abc123
    owner: platform@example.com
    reason: Temporary exposure during migration; protected by IP allowlist.
    created_at: 2026-05-29
    expires_at: 2026-06-30
    conditions:
      environment: staging
      evidence_fingerprint: abc123
```

Waiver files do not store evidence values or secrets. They store only review metadata and matching scope.

## Add a waiver

```bash
changegate waiver add \
  --file .changegate/waivers.yaml \
  --rule AWS_PUBLIC_RDS_INSTANCE \
  --resource aws_db_instance.analytics_replica \
  --fingerprint abc123 \
  --owner platform@example.com \
  --reason "Temporary exposure during migration." \
  --expires-at 2026-06-30 \
  --environment staging \
  --evidence-fingerprint abc123
```

`owner`, `reason`, and `expires-at` are required by default. Prefer exact `fingerprint` scope when possible.

## Validate, list, prune

```bash
changegate waiver list --file .changegate/waivers.yaml
changegate waiver validate --file .changegate/waivers.yaml --max-duration-days 90
changegate waiver prune --file .changegate/waivers.yaml
```

Validation fails malformed waivers and warns on broad or expired waivers. Prune removes expired waiver records.

## Review against current findings

```bash
changegate waiver report \
  --file .changegate/waivers.yaml \
  --plan tfplan.json
```

The report explains which waivers applied, which were invalidated, and which were unused.

## Scan integration

Reference the waiver file in policy:

```yaml
version: 1
waivers:
  file: .changegate/waivers.yaml
  require_expiration: true
  max_duration_days: 90
  fail_expired: true
```

Active matching waivers suppress findings and add `SUPPRESSED` decision reasons. Expired waivers do not suppress. With `fail_expired: true`, any expired waiver in the configured file fails policy before enforcement.

## Invalidation rules

A waiver does not apply when:

* the resource address changes and the waiver is resource-scoped
* the environment condition no longer matches
* the finding fingerprint no longer matches
* `conditions.evidence_fingerprint` no longer matches the current finding fingerprint
* the policy pack major version condition no longer matches, when present
* `expires_at` has passed
