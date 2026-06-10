# Remediation

ChangeGate findings include developer-facing remediation in the canonical report. Guidance is advisory by default: ChangeGate can show Terraform/OpenTofu snippets and patch suggestions, but it does not automatically rewrite infrastructure code for destructive, exposure, IAM, or topology-sensitive changes.

## Explain a rule

```bash
changegate explain AWS_PUBLIC_ADMIN_SERVICE
changegate explain AWS_PUBLIC_ADMIN_SERVICE --json
```

The output includes:

- what happened
- why it matters
- recommended fix
- why the fix works
- fix confidence
- effort and downtime-risk estimates
- whether the change is potentially destructive
- fix options with operational tradeoffs
- Terraform/OpenTofu resource and attribute hints
- advisory patch snippets when safe enough to suggest
- severity-specific next steps

## Explain a finding from a report

```bash
changegate scan --plan tfplan.json --format json --out changegate.json
changegate explain CHG-1234567890ABCDEF --report changegate.json
```

The argument can be a finding ID, rule ID, or fingerprint from the report.

## Patch suggestions

Remediation metadata is machine-readable in JSON, SARIF properties, PR comments, and audit bundles. A finding can include structured fields such as:

```json
{
  "effort": "medium",
  "downtime_risk": "low",
  "destructive": false,
  "fix_options": [
    {
      "title": "Restrict ingress",
      "description": "Keep the endpoint public only for reviewed CIDRs or authenticated edge controls.",
      "effort": "low",
      "downtime_risk": "low",
      "preferred": true
    }
  ],
  "terraform_hints": [
    {
      "resource_type": "aws_security_group_rule",
      "attribute": "cidr_blocks",
      "preferred": "trusted CIDRs only",
      "notes": "Avoid 0.0.0.0/0 and ::/0 for administrative or data paths."
    }
  ]
}
```

These fields are guidance, not enforcement inputs. Policy decisions still come from deterministic rule severity, confidence, baselines, waivers, and policy thresholds.

Patch suggestions use a structured format:

```json
{
  "title": "Restrict security group ingress",
  "format": "terraform-snippet",
  "language": "hcl",
  "snippet": "ingress { ... }",
  "safe_to_apply": false,
  "rationale": "Snippet is advisory because variable names, module boundaries, and environment intent must be reviewed before use.",
  "review_needed": true
}
```

`safe_to_apply` is currently `false` for all built-in remediation. This is intentional. The CLI distinguishes helpful snippets from automatic patches so it never silently changes risky infrastructure semantics.

Attack-path remediation is always advisory. Public-to-sensitive, public-admin, PassRole, and AssumeRole paths usually require topology, access-model, or deployment-workflow review. ChangeGate reports the smallest path evidence it can prove, then suggests safe review directions such as restricting ingress, segmenting sensitive assets, narrowing `iam:PassRole`, or constraining role trust. It does not automatically rewrite multi-resource graph paths or IAM trust policies.

## Organization Documentation Links

Attach organization-specific documentation to remediation output through `.changegate.yaml`:

```yaml
docs:
  links:
    default: https://docs.example.com/security/changegate
    public_exposure: https://docs.example.com/security/public-exposure
    AWS_PUBLIC_ADMIN_SERVICE: https://docs.example.com/security/admin-services
```

Keys can be a rule ID, risk category, provider label such as `aws`, or `default`.

## Owner hints

When Terraform/OpenTofu plan tags include `owner`, `team`, `service`, `application`, or `app`, ChangeGate copies those values into remediation `owner_hints`. This gives reviewers a practical routing hint without requiring live cloud credentials.
