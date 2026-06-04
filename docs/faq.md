# FAQ

## Does ChangeGate need cloud credentials?

No. The default scan reads only Terraform/OpenTofu plan JSON. Optional cloud context is file-based and opt-in.

## Does ChangeGate replace Terraform policy tools?

No. It is a risk gate focused on high-confidence infrastructure changes before apply. It can complement Sentinel, OPA, Checkov, Trivy, KICS, and other tools.

## Why analyze the plan instead of static Terraform files?

The plan shows the concrete actions Terraform/OpenTofu intends to apply. ChangeGate uses those actions plus graph relationships to avoid blocking unrelated static configuration.

## Does ChangeGate use AI to make decisions?

No. Allow/warn/block decisions are deterministic policy evaluations. Any explanation or remediation text is separate from the deployment decision.

## How do I handle existing known risk?

Create a baseline and scan with `--new-only`.

## How do I handle legitimate exceptions?

Use waivers with owner, reason, scope, and expiration.

## Can it scan multiple plans?

Yes. Repeat `--plan` when one policy owner should gate a coordinated change. For separate owners, run separate jobs.

## What happens when ChangeGate blocks?

The scan returns exit code `1` and includes decision reasons and remediation guidance.
