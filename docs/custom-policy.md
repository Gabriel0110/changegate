# Custom Policy

ChangeGate supports customization without dynamic Go plugins. Built-in Go rules remain the recommended path for high-confidence graph analysis; custom policy is opt-in through `.changegate.yaml`.

## Enable custom YAML rules

```yaml
version: 1

custom_rules:
  files:
    - rules/*.yaml
  max_file_size: 1048576
```

Paths are resolved relative to the policy file. Globs are supported. Malformed custom rules fail `changegate policy validate` and fail scans before evaluation.

`custom_rules.required` controls empty glob behavior. When `false` or omitted, an empty optional custom-rule directory is allowed so teams can share one policy file across repos. When `true`, an empty glob fails `policy validate`.

## YAML rule format

```yaml
id: ORG_PUBLIC_ADMIN
title: Public admin services are not allowed in production
description: Public admin paths should not be deployed from pull requests.
category: public_exposure
severity: critical
confidence: high
select:
  type: aws_lb
where:
  all:
    - field: scheme
      equals: internet-facing
    - graph.routes_to.tag:
        key: service_type
        value: admin
    - graph.internet_exposed: true
remediation: Place admin service behind VPN, private ALB, or authenticated proxy.
references:
  - https://example.com/security/admin-access-standard
```

Rule files can also contain multiple rules:

```yaml
rules:
  - id: ORG_QUEUE_REVIEW
    title: SQS queue changes require review
    category: compliance
    severity: high
    confidence: high
    select:
      type: aws_sqs_queue
    where:
      field: name
      equals: jobs
    remediation: Review queue access policy.
```

## Selectors

`select` restricts which changed resources a rule evaluates:

| Field      | Meaning                                                                                |
| ---------- | -------------------------------------------------------------------------------------- |
| `type`     | Terraform/OpenTofu resource type, such as `aws_lb`.                                    |
| `provider` | Provider substring, such as `hashicorp/aws`.                                           |
| `address`  | Exact resource address.                                                                |
| `tags`     | Exact tag key/value matches.                                                           |
| `actions`  | Any matching plan action: `create`, `update`, `delete`, `replace`, `read`, or `no-op`. |

## Conditions

`where` supports boolean composition and field checks:

| Syntax       | Meaning                                   |
| ------------ | ----------------------------------------- |
| `all`        | Every nested condition must match.        |
| `any`        | At least one nested condition must match. |
| `not`        | Nested condition must not match.          |
| `field`      | Field path over the changed resource.     |
| `equals`     | Case-insensitive equality.                |
| `not_equals` | Case-insensitive inequality.              |
| `contains`   | Case-insensitive substring match.         |
| `in`         | Value must match one item in the list.    |
| `exists`     | Field existence check.                    |

Field paths can reference `address`, `name`, `type`, `provider`, `tags.<key>`, `before.<path>`, and `after.<path>`. Unqualified field names read from `after`.

## Graph predicates

Custom YAML rules can reference graph context:

| Predicate                     | Meaning                                                                             |
| ----------------------------- | ----------------------------------------------------------------------------------- |
| `graph.routes_to.tag`         | The selected resource routes to or attaches to a graph node with the tag key/value. |
| `graph.internet_exposed`      | The graph proves whether the selected resource is internet-exposed.                 |
| `graph.sensitive_data_access` | The graph proves whether the selected resource can read or write sensitive data.    |

## Optional OPA/Rego

OPA/Rego support is disabled unless the policy config includes `rego.files`:

```yaml
version: 1

rego:
  files:
    - policy/*.rego
  query: data.changegate.findings
  timeout: 250ms
  max_input_bytes: 5242880
```

Rego modules should return a finding object or a collection of finding objects:

```rego
package changegate

findings contains f if {
  change := input.changes[_]
  change.type == "aws_sqs_queue"
  f := {
    "rule_id": "ORG_QUEUE_REVIEW",
    "title": "SQS queue requires review",
    "resource_address": change.address,
    "category": "compliance",
    "severity": "high",
    "confidence": "high",
    "remediation": "Review queue access policy."
  }
}
```

ChangeGate rejects Rego modules that use network/runtime-oriented builtins such as `http.send`, `net.lookup_ip_addr`, and `opa.runtime`. Evaluation uses a context timeout and a maximum serialized input size. The Terraform/OpenTofu plan model is already redacted before it reaches Rego.

`policy validate` compiles configured Rego modules and queries before scan time. Syntax errors, invalid queries, unsafe builtins, missing files, and oversized input settings fail validation so CI can catch policy authoring problems before evaluating a plan.

## Test locally

```bash
changegate policy validate .changegate.yaml
changegate policy test .changegate.yaml
changegate scan --policy .changegate.yaml --plan tfplan.json
```

`policy validate` checks YAML syntax, custom rule schemas, Rego sandbox constraints, policy packs, rule references, baselines, and waivers. `policy test` reports selected and registered rule counts without requiring a plan.
