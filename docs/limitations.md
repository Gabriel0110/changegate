# Known Limitations

ChangeGate is designed to be conservative, deterministic, and useful in CI. It is not a full cloud security platform, runtime scanner, or attack simulator. These boundaries are intentional.

## Scope

ChangeGate currently focuses on Terraform/OpenTofu plan JSON. It does not primarily scan raw Terraform source files, CloudFormation, Kubernetes manifests, Helm charts, Pulumi programs, or live cloud accounts.

AWS has the broadest built-in rule coverage. Other providers can still be represented in plan, graph, custom policy, and imported scanner outputs, but first-party high-confidence rules are AWS-first.

## Plan Evidence

ChangeGate can only reason from the plan JSON and any explicitly supplied offline context files. Unknown Terraform values, provider-computed attributes, missing references, or module abstractions can reduce graph confidence.

When evidence is incomplete or ambiguous, ChangeGate should warn or lower confidence instead of producing a high-confidence block.

## Cloud Context

Normal scans are offline and credential-free. AWS context collection is opt-in through `changegate context aws snapshot --collect`.

Cloud context is a redacted snapshot, not continuous monitoring. It can improve graph evidence for attachments, public exposure, routing, IAM trust, data assets, and drift-like context, but it is not a replacement for CSPM, CNAPP, runtime inventory, or incident response tooling.

Partial AWS permissions are expected. ChangeGate records snapshot diagnostics and continues with the context it can safely collect.

## Attack Paths

Attack paths are deterministic review evidence. They are not a full exploit simulator.

Current high-confidence paths focus on:

- public entrypoint to workload to sensitive datastore, secret, or key
- principal to `iam:PassRole`, `sts:AssumeRole`, Lambda mutation, or ECS mutation paths that reach admin or sensitive access

Ambiguous graph or IAM evidence lowers confidence and should not create high-confidence blocking findings.

## Rules And False Positives

The built-in rule pack is intentionally high-confidence. This means ChangeGate will miss some risky patterns that require local context, business intent, runtime configuration, or broad static analysis.

Use external scanner imports when you want broad coverage from tools like Checkov, Trivy, KICS, Grype, or other SARIF producers. Use ChangeGate to correlate that evidence with the planned deployment decision.

## Human Review

ChangeGate is a deployment gate, not a substitute for human architecture review. Large topology changes, production data migrations, account boundary changes, and accepted exceptions still need accountable review.

Waivers should be scoped, owned, justified, and time-bound. Broad permanent waivers reduce the value of any risk gate.

## Stability

ChangeGate is on the stable `v1.x` release line. Exit codes, core report schema names, release verification behavior, and stable rule IDs are intended to remain compatible within `v1.x`. New rules, output fields, and visualization capabilities may be added in minor releases.
