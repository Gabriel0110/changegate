# Terraform Cloud/Enterprise Run Task Guidance

ChangeGate does not require cloud credentials or a SaaS account, so the recommended Terraform Cloud/Enterprise pattern is an external worker:

1. Receive the run-task callback in your existing automation service.
2. Download or obtain the plan JSON for the run.
3. Run `changegate scan --plan tfplan.json --format json`.
4. Convert the ChangeGate decision to the run-task status response used by your automation.

Use `--mode audit` during rollout, then enforce once the finding stream is understood.
