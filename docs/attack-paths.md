# Attack Paths

Attack paths are first-class ChangeGate evidence objects. They explain how a planned or live-context infrastructure relationship could become an exploitable path, not just that a risky setting exists.

The v2/v3 model supports two categories:

- `public_to_sensitive_data`: a public entrypoint can reach a sensitive datastore, secret, or key.
- `iam_privilege_escalation`: a principal can reach admin or sensitive access through high-signal IAM actions, role trust, policy mutation, or chained role assumption.

The detector commands are available through `changegate attack-paths`, and high-confidence attack paths are integrated into scan, impact, review comment, and audit-bundle output when attack-path policy is enabled.

```bash
changegate attack-paths --plan tfplan.json
changegate attack-paths --plan tfplan.json --to-sensitive-data
changegate attack-paths --plan tfplan.json --principal aws_iam_role.github_actions
changegate attack-paths --plan tfplan.json --format json --out attack-paths.json
changegate attack-paths --plan tfplan.json --format dot --out attack-paths.dot
changegate attack-paths --plan tfplan.json --format mermaid --out attack-paths.mmd
changegate attack-paths visualize --plan tfplan.json --out attack-paths.html
```

DOT and Mermaid output work well when diagrams are already published in docs or CI artifacts. `attack-paths visualize` writes a self-contained interactive HTML file with highlighted path edges, role filters, search, and a node evidence inspector. It is the preferred human review artifact when JSON is too dense for pull-request review.

Public-to-sensitive detection uses the blast-radius graph to find public entrypoint paths that pass through a workload and reach a sensitive asset. High-confidence paths to sensitive data block by default; medium-confidence paths warn. Public paths to workloads without sensitive downstream context warn unless the entrypoint is explicitly marked as expected public through tags or cloud context compensating controls such as `expected_public_tls_edge`, `edge_tls`, `waf`, `cloudfront_oac`, or `ip_allowlist`.

Network attack paths include:

- public API Gateway routes that invoke workloads with downstream secret or data access
- public Lambda Function URLs that invoke functions with secret, KMS, S3, or datastore access
- public workloads that can reach RDS, OpenSearch, ElastiCache, EFS, S3, Secrets Manager, or KMS
- public EKS endpoints with graph evidence of cluster-admin or privileged role access

Sensitive assets include common AWS data stores, secrets, and KMS keys by default. Extend classification with `.changegate.yaml` selectors for resource addresses, resource types, names, and tags; see [Policy Config Guide](policy-config.md#sensitive-assets). This lets private data platforms, backup vaults, or custom provider resources participate in attack paths and graph-aware rules.

When an optional AWS cloud-context snapshot is merged into the graph, attack paths preserve provenance. A path can report `source=plan`, `source=cloud_context`, or `source=mixed` when live AWS context confirms or extends planned graph evidence. Cloud-confirmed edges can raise confidence; partial or ambiguous context lowers confidence and produces warning-oriented output.

IAM privilege-escalation detection normalizes IAM action wildcards, service wildcards, resource wildcards, explicit deny statements, complex conditions, and `NotAction`/`NotResource` semantics. The detector focuses on high-signal paths: `iam:PassRole` plus compute mutation, `sts:AssumeRole` to admin or sensitive roles, Lambda code/configuration updates or function creation into privileged execution roles, ECS service/task-definition mutation into sensitive task roles, chained role assumptions, and IAM policy mutation patterns such as inline policy attachment, managed policy attachment, default policy version promotion, trust policy rewrite plus assume-role, and privileged user access-key or login-profile creation. Complex conditions, explicit deny ambiguity, or broad `NotAction` semantics reduce confidence and produce warnings rather than high-confidence blocks.

ChangeGate also embeds a compact detection snapshot from the public [DataDog/pathfinding.cloud](https://github.com/DataDog/pathfinding.cloud) IAM privilege-escalation catalog. That snapshot contains the catalog path ID, name, category, services, required IAM actions, references, and source path for 86 AWS IAM escalation paths. ChangeGate evaluates those prerequisites natively against Terraform/OpenTofu plan graph evidence and optional cloud-context evidence; it does not fetch, execute, or shell out to pathfinding.cloud at scan time.

Catalog-backed paths produce `AWS_IAM_PATHFINDING_CATALOG_ESCALATION` findings when attack-path policy includes them. New PassRole paths require both `iam:PassRole` and the service-specific mutation actions, and they only block when ChangeGate can identify a privileged or sensitive role target. Existing-resource paths require graph evidence that the affected resource already uses a privileged or sensitive role. Ambiguous IAM semantics, `NotAction`, policy conditions, or incomplete target evidence lower confidence and produce warnings or no path instead of a high-confidence block.

## Contract

Attack path JSON uses schema version 2 and is documented by [`schemas/attack-paths.schema.json`](../schemas/attack-paths.schema.json). Version 2 keeps the core v1 fields and adds first-class context for review and audit workflows:

- `kind`: the path domain, such as `network` or `identity`.
- `source`: whether the path came from plan evidence, cloud context, inference, or mixed evidence.
- `confidence_reason`: the concise reason ChangeGate assigned the path confidence.
- `affected_resources`: the resources that participate in the path and their role in it.
- `finding_rule_ids`: the deploy-decision rules that can be produced from the path.
- step-level `source`, `confidence`, `evidence`, and `metadata`.

```json
{
  "version": 2,
  "paths": [
    {
      "id": "attack-path-public-admin",
      "type": "public_to_sensitive_data",
      "kind": "network",
      "title": "Public admin service reaches customer database",
      "severity": "critical",
      "confidence": "high",
      "confidence_reason": "high confidence: every step from public entrypoint through workload to sensitive target is backed by explicit plan or cloud-context graph evidence",
      "decision": "block",
      "source": "plan",
      "entrypoint": "aws_lb.admin",
      "target": "aws_db_instance.customer",
      "affected_resources": [
        {
          "resource": "aws_lb.admin",
          "role": "entrypoint",
          "type": "aws_lb"
        },
        {
          "resource": "aws_db_instance.customer",
          "role": "sensitive_asset",
          "type": "aws_db_instance"
        }
      ],
      "finding_rule_ids": ["AWS_PUBLIC_TO_SENSITIVE_DATA_PATH"],
      "steps": [
        {
          "from": "internet",
          "to": "aws_lb.admin",
          "action": "public HTTP ingress",
          "edge_type": "routes_to",
          "source": "plan",
          "confidence": "high",
          "explanation": "internet-facing load balancer accepts public traffic"
        }
      ]
    }
  ]
}
```

## Policy Eligibility

Attack paths are deterministic evidence. They can affect deployment decisions only when attack path analysis is enabled and the path confidence is high. Medium-confidence paths can be rendered as warnings when explicitly configured, but they should not create high-confidence blocking decisions.

This keeps ChangeGate’s enforcement posture conservative while still giving reviewers useful context for ambiguous paths.

## Current Scope

Attack Paths v2/v3 is intentionally deterministic rather than exhaustive. It focuses on high-signal infrastructure changes that are practical to gate before apply:

- public entrypoint to workload to sensitive datastore, secret, or key
- public API Gateway and Lambda Function URL paths into sensitive access
- public EKS endpoint paths into cluster-admin or privileged role access
- principal to `iam:PassRole`, `sts:AssumeRole`, Lambda update, ECS update, IAM policy mutation, pathfinding.cloud catalog prerequisites, or multi-role assumption chains that reach admin or sensitive access
- broad `NotAction` or wildcard-resource IAM patterns when they imply escalation actions

When graph or IAM evidence is ambiguous, detectors lower confidence and produce warning-oriented evidence instead of pretending the path is certain.
