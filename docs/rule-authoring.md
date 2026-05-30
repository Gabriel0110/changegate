# Rule Authoring

ChangeGate rules should be narrow, explainable, deterministic, and high confidence. A rule should block only when the plan evidence is strong enough that a maintainer would defend the decision in CI.

## Rule Contract

Every built-in rule needs:

* a stable rule ID
* severity and confidence metadata
* a short human-readable title
* evidence fields that explain why the rule fired
* remediation guidance
* table-driven tests
* generated rule documentation
* a changelog entry when default behavior changes

Use an ID in the existing namespace style, for example `AWS_S3_PUBLIC_ACCESS_BLOCK_DISABLED_PROD`. Do not reuse or rename rule IDs after release. If a rule must be replaced, deprecate the old ID and introduce a new one.

## Implementation Steps

1. Add metadata in the rule implementation under `internal/rules`.
2. Implement the smallest predicate that proves the risk from plan, graph, context, or cloud-context evidence.
3. Attach evidence to each finding. Evidence should be concrete resource fields, graph relationships, or matched policy conditions.
4. Add remediation text in `internal/remediation`.
5. Add table-driven tests in `internal/rules`.
6. Run `scripts/generate-rule-docs.sh docs/rules`.
7. Add a `CHANGELOG.md` entry when the rule is new, removed, promoted, deprecated, or changes default severity/confidence.

## Test Requirements

Rule tests must include:

* a positive case where the rule fires
* a negative case where similar safe infrastructure does not fire
* environment/context coverage when the rule changes behavior for production or sensitive resources
* graph coverage for graph-aware rules
* waiver or baseline coverage only when the rule adds special suppression behavior

Prefer focused fixtures over large real plans. If a test needs a full Terraform/OpenTofu plan, sanitize it with the fixture guidance in [fixtures](fixtures.md).

## Blocking Rules

Blocking rules should normally satisfy all of these conditions:

* the resource action is in the current plan
* the dangerous attribute is explicit or can be proven from graph/context evidence
* the remediation is actionable
* the rule has low expected false positives
* uncertainty is expressed as warning, not block

When in doubt, start a rule as warning or experimental, document the limitation, and promote only after fixtures and false-positive reports support it.

## Graph-Aware Rules

Graph-aware rules should include the graph path in finding evidence whenever possible. For example, a public load balancer connected to a security group and sensitive datastore should show the path that made the exposure meaningful.

Graph evidence should not be decorative. Use it only when the relationship changes the risk decision or confidence.

## Custom Policy Examples

For organization-specific logic, prefer custom YAML or Rego policies before adding a built-in rule. Built-ins should protect common infrastructure patterns across many users.

See [custom policy](custom-policy.md) for the custom policy input contract.
