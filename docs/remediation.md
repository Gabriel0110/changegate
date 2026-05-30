# Remediation

ChangeGate findings include developer-facing remediation in the canonical report. Guidance is advisory by default: ChangeGate can show Terraform/OpenTofu snippets and patch suggestions, but it does not automatically rewrite infrastructure code for destructive, exposure, IAM, or topology-sensitive changes.

## Explain a rule

```bash
changegate explain AWS_PUBLIC_ADMIN_SERVICE
changegate explain AWS_PUBLIC_ADMIN_SERVICE --json
```

The output includes:

* what happened
* why it matters
* recommended fix
* why the fix works
* fix confidence
* advisory patch snippets when safe enough to suggest
* severity-specific next steps

## Explain a finding from a report

```bash
changegate scan --plan tfplan.json --format json --out changegate.json
changegate explain CHG-1234567890ABCDEF --report changegate.json
```

The argument can be a finding ID, rule ID, or fingerprint from the report.

## Patch suggestions

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

## Internal docs links

Teams can attach internal documentation to remediation output through `.changegate.yaml`:

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
